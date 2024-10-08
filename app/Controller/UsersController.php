<?php
App::uses('AppController', 'Controller');

/**
 * @property User $User
 */
class UsersController extends AppController
{
    public $newkey;

    public $components = array(
        'RequestHandler'
    );

    public $paginate = array(
        'limit' => 60,
        'recursive' => -1,
        'order' => array(
                'Organisation.name' => 'ASC'
        ),
        'contain' => array(
            'Organisation' => array('id', 'uuid', 'name'),
            'Role' => array('id', 'name', 'perm_auth', 'perm_site_admin', 'perm_admin')
        )
    );

    public function beforeFilter()
    {
        parent::beforeFilter();

        // what pages are allowed for non-logged-in users
        $allowedActions = array('login', 'logout', 'getGpgPublicKey', 'logout401', 'otp', 'heartbeat');
        if (!empty(Configure::read('Security.allow_password_forgotten'))) {
            $allowedActions[] = 'forgot';
            $allowedActions[] = 'password_reset';
        }
        if(!empty(Configure::read('Security.email_otp_enabled'))) {
          $allowedActions[] = 'email_otp';
        }
        if (!empty(Configure::read('Security.allow_self_registration'))) {
            $allowedActions[] = 'register';
        }
        $this->Auth->allow($allowedActions);
    }

    public function view($id = null)
    {
        if ("me" === $id) {
            $id = $this->Auth->user('id');
        }
        if (!$this->_isSiteAdmin() && $this->Auth->user('id') != $id) {
            throw new NotFoundException(__('Invalid user or not authorised.'));
        }
        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => array('User.id' => $id),
            'contain' => array(
                'UserSetting',
                'Role',
                'Organisation'
            )
        ));
        if (empty($user)) {
            throw new NotFoundException(__('Invalid user'));
        }
        if (!empty(Configure::read('Security.advanced_authkeys'))) {
            unset($user['User']['authkey']);
        }
        if (!empty($user['User']['gpgkey'])) {
            $pgpDetails = $this->User->verifySingleGPG($user);
            $user['User']['pgp_status'] = isset($pgpDetails[2]) ? $pgpDetails[2] : 'OK';
            $user['User']['fingerprint'] = !empty($pgpDetails[4]) ? $pgpDetails[4] : 'N/A';
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($this->__massageUserObject($user), $this->response->type());
        } else {
            $this->set('user', $user);
            $this->set('admin_view', false);
            $this->set('periodic_notifications', $this->User::PERIODIC_NOTIFICATIONS);
        }
    }

    /**
     * @param array $user
     * @return array
     */
    private function __massageUserObject(array $user)
    {
        $user['UserSetting'] = array_column($user['UserSetting'], 'value', 'setting');
        unset($user['User']['server_id']);
        if (!empty(Configure::read('Security.advanced_authkeys'))) {
            unset($user['User']['authkey']);
        }
        $user['User']['password'] = '*****';
        $user['User']['totp'] = '*****';
        $temp = [];
        $objectsToInclude = array('User', 'Role', 'UserSetting', 'Organisation');
        foreach ($objectsToInclude as $objectToInclude) {
            if (isset($user[$objectToInclude])) {
                $temp[$objectToInclude] = $user[$objectToInclude];
            }
        }
        return $temp;
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

    public function unsubscribe($code, $type = null)
    {
        if ($type === null) {
            $type = 'autoalert';
        } else if (!in_array($type, ['autoalert', 'notification_daily', 'notification_weekly', 'notification_monthly'], true)) {
            throw new NotFoundException("Invalid type $type.");
        }

        $user = $this->Auth->user();

        if (!hash_equals($this->User->unsubscribeCode($user), rtrim($code, '.'))) {
            $this->Flash->error(__('Invalid unsubscribe code.'));
            $this->redirect(['action' => 'view', 'me']);
        }

        if ($user[$type]) {
            $this->User->updateField($user, $type, false);
            $this->Flash->success(__('Successfully unsubscribed from notification.'));
        } else {
            $this->Flash->info(__('Already unsubscribed from notification.'));
        }
        $this->redirect(['action' => 'view', 'me']);
    }

    public function edit()
    {
        $currentUser = $this->User->find('first', array(
            'conditions' => array('User.id' => $this->Auth->user('id')),
            'recursive' => -1
        ));
        if (empty($currentUser)) {
            throw new NotFoundException('Something went wrong. Your user account could not be accessed.');
        }
        $id = $currentUser['User']['id'];
        if ($this->request->is('post') || $this->request->is('put')) {
            if (empty($this->request->data['User'])) {
                $this->request->data = array('User' => $this->request->data);
            }
            $abortPost = false;
            if (!empty($this->request->data['User']['email']) && !$this->_isSiteAdmin()) {
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
                        $message = __('Invalid e-mail domain. Your user is restricted to creating users for the following domain(s): ') . implode(', ', $organisation['Organisation']['restricted_to_domain']);
                    }
                }
            }
            if (!$abortPost && (!$this->_isRest() || empty($this->request->header('Authorization')))) {
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
                $fieldList = array('autoalert', 'gpgkey', 'certif_public', 'nids_sid', 'contactalert', 'disabled', 'date_modified', 'notification_daily', 'notification_weekly', 'notification_monthly');
                if ($this->__canChangeLogin()) {
                    $fieldList[] = 'email';
                }
                if ($this->__canChangePassword() && !empty($this->request->data['User']['password'])) {
                    $fieldList[] = 'password';
                    $fieldList[] = 'confirm_password';
                }
                foreach ($this->request->data['User'] as $k => $v) {
                    $currentUser['User'][$k] = $v;
                }
                // Save the data
                if ($this->_isRest()) {
                    if (!empty($this->request->data['User']['password'])) {
                        if ($this->request->data['User']['password'] === '*****') {
                            unset($this->request->data['User']['password']);
                        } else {
                            $currentUser['User']['confirm_password'] = $this->request->data['User']['password'];
                        }
                    }
                }
                if ($this->User->save($currentUser, true, $fieldList)) {
                    if ($this->_isRest()) {
                        $user = $this->User->find('first', array(
                            'conditions' => array('User.id' => $id),
                            'recursive' => -1,
                            'contain' => array(
                                'Organisation',
                                'Role',
                                'UserSetting'
                            )
                        ));
                        return $this->RestResponse->viewData($this->__massageUserObject($user), $this->response->type());
                    } else {
                        $this->Flash->success(__('The profile has been updated'));
                        $this->redirect(array('action' => 'view', $id));
                    }
                } else {
                    $message = __('The profile could not be updated. Please, try again.');
                    $abortPost = true;
                }
            }
            if ($abortPost) {
                $this->request->data['User']['password'] = '';
                $this->request->data['User']['confirm_password'] = '';
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Users', 'edit', $id, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                }
            }
        } else {
            $this->User->data = $currentUser;
            $this->User->set('password', '');
            $this->request->data = $this->User->data;
        }
        $this->loadModel('Server');
        $this->set('complexity', !empty(Configure::read('Security.password_policy_complexity')) ? Configure::read('Security.password_policy_complexity') : $this->Server->serverSettings['Security']['password_policy_complexity']['value']);
        $this->set('length', !empty(Configure::read('Security.password_policy_length')) ? Configure::read('Security.password_policy_length') : $this->Server->serverSettings['Security']['password_policy_length']['value']);
        $roles = $this->User->Role->find('list');
        $this->set('roles', $roles);
        $this->set('id', $id);
        $this->set('canChangePassword', $this->__canChangePassword());
        $this->set('canChangeLogin', $this->__canChangeLogin());
        $this->set('canFetchPgpKey', $this->__canFetchPgpKey());
    }

    private function __pw_change($user, $source, &$abortPost, $token = false, $skip_password_confirmation = false)
    {
        if (!isset($this->request->data['User'])) {
            $this->request->data = array('User' => $this->request->data);
        }
        if (Configure::read('Security.require_password_confirmation') && !$skip_password_confirmation) {
            if (!empty($this->request->data['User']['current_password'])) {
                $hashed = $this->User->verifyPassword($this->Auth->user('id'), $this->request->data['User']['current_password']);
                if (!$hashed) {
                    $message = __('Invalid password. Please enter your current password to continue.');
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('Users', $source, false, $message, $this->response->type());
                    }
                    $abortPost = true;
                    $this->Flash->error($message);
                }
                unset($this->request->data['User']['current_password']);
            } else if (!$this->_isRest()) {
                $message = __('Please enter your current password to continue.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Users', $source, false, $message, $this->response->type());
                }
                $abortPost = true;
                $this->Flash->info($message);
            }
        }
        $hashed = $this->User->verifyPassword($this->Auth->user('id'), $this->request->data['User']['password']);
        if ($hashed) {
            $message = __('Submitted new password cannot be the same as the current one');
            $abortPost = true;
        }
        if (!$abortPost) {
            // What fields should be saved (allowed to be saved)
            $user['User']['change_pw'] = 0;
            $user['User']['password'] = $this->request->data['User']['password'];
            $user['User']['last_pw_change'] = time();
            if ($this->_isRest()) {
                $user['User']['confirm_password'] = $this->request->data['User']['password'];
            } else {
                $user['User']['confirm_password'] = $this->request->data['User']['confirm_password'];
            }
            $temp = $user['User']['password'];
            // Save the data
            if ($this->User->save($user)) {
                if ($token) {
                    $this->User->purgeForgetToken($token);
                }
                $message = __('Password Changed.');
                // log as System if the reset comes from an unauthed user using password_reset tokens
                $logUser = empty($this->Auth->user()) ? 'SYSTEM' : $this->Auth->user();
                $this->User->extralog($logUser, $source, null, null, $user);
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('User', $source, false, $this->response->type(), $message);
                }
                $this->Flash->success($message);
                $this->redirect(array('action' => 'view', $user['User']['id']));
            } else {
                $message = __('The password could not be updated. Make sure you meet the minimum password length / complexity requirements.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Users', $source, false, $message, $this->response->type());
                }
                $this->Flash->error($message);
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Users', $source, false, $message, $this->response->type());
            } else {
                $this->Flash->error($message);
            }
        }
    }

    public function change_pw()
    {
        $id = $this->Auth->user('id');
        $user = $this->User->find('first', array(
            'conditions' => array('User.id' => $id),
            'recursive' => -1
        ));
        if ($this->request->is('post') || $this->request->is('put')) {
            $abortPost = false;
            return $this->__pw_change($user, 'change_pw', $abortPost);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->describe('Users', 'change_pw', false, $this->response->type());
        }
        $this->loadModel('Server');
        $this->set('complexity', !empty(Configure::read('Security.password_policy_complexity')) ? Configure::read('Security.password_policy_complexity') : $this->Server->serverSettings['Security']['password_policy_complexity']['value']);
        $this->set('length', !empty(Configure::read('Security.password_policy_length')) ? Configure::read('Security.password_policy_length') : $this->Server->serverSettings['Security']['password_policy_length']['value']);
        $this->User->recursive = 0;
        $this->User->read(null, $id);
        $this->User->set('password', '');
        $this->request->data = $this->User->data;
        $roles = $this->User->Role->find('list');
        $this->set('roles', $roles);
    }

    public function admin_index()
    {
        $this->User->virtualFields['org_ci'] = 'UPPER(Organisation.name)';
        $urlParams = "";
        $passedArgsArray = array();
        $booleanFields = array('autoalert', 'contactalert', 'termsaccepted', 'disabled');
        $textFields = array('role', 'email', 'all', 'authkey');
        // org admins can't see users of other orgs
        if ($this->_isSiteAdmin()) {
            $textFields[] = 'org';
        }
        $this->set('passedArgs', json_encode($this->passedArgs));
        // check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
        if (!empty($this->passedArgs['value'])) {
            $this->passedArgs['searchall'] = $this->passedArgs['value'];
        }
        foreach ($this->passedArgs as $k => $v) {
            if (substr($k, 0, 6) === 'search') {
                if ($v != "") {
                    if ($urlParams != "") {
                        $urlParams .= "/";
                    }
                    $urlParams .= $k . ":" . $v;
                }
                $searchTerm = substr($k, 6);
                if (in_array($searchTerm, $booleanFields, true)) {
                    if ($v != "") {
                        $this->paginate['conditions'][] = array('User.' . $searchTerm => $v);
                    }
                } elseif (in_array($searchTerm, $textFields, true)) {
                    if ($v != "") {
                        if ($searchTerm == "role") {
                            $searchTerm = "role_id";
                        }
                        $pieces = explode('|', $v);
                        $test = array();
                        foreach ($pieces as $piece) {
                            if ($piece[0] === '!') {
                                if ($searchTerm === 'email') {
                                    $this->paginate['conditions']['AND'][] = array('LOWER(User.' . $searchTerm . ') NOT LIKE' => '%' . strtolower(substr($piece, 1)) . '%');
                                } elseif ($searchTerm === 'org') {
                                    $this->paginate['conditions']['AND'][] = array('User.org_id !=' => substr($piece, 1));
                                } else {
                                    $this->paginate['conditions']['AND'][] = array('User.' . $searchTerm => substr($piece, 1));
                                }
                            } else {
                                if ($searchTerm === 'email') {
                                    $test['OR'][] = array('LOWER(User.' . $searchTerm . ') LIKE' => '%' . strtolower($piece) . '%');
                                } elseif ($searchTerm === 'org') {
                                    $this->paginate['conditions']['OR'][] = array('User.org_id' => $piece);
                                } elseif ($searchTerm === 'all') {
                                    $searchValue = '%' . mb_strtoupper($piece) . '%';
                                    $this->paginate['conditions']['AND'][] = array(
                                        'OR' => array(
                                            'UPPER(User.email) LIKE' => $searchValue,
                                            'UPPER(Organisation.name) LIKE' => $searchValue,
                                            'UPPER(Role.name) LIKE' => $searchValue
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
                } elseif ("inactive" == $searchTerm) {
                    if ($v == "1") {
                        $this->paginate['conditions']['AND'][] = array('User.last_login <' =>  time() - 60*60*24*30);  // older than a month
                        $this->paginate['conditions']['AND'][] = array('User.current_login <' =>  time() - 60*60*24*30);  // older than a month
                        $this->paginate['conditions']['AND'][] = array('User.last_api_access <' =>  time() - 60*60*24*30);  // older than a month
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
                    'last_api_access',
                    'force_logout',
                    'date_created',
                    'date_modified',
                    'last_pw_change',
                    'totp'
                ),
                'contain' => array(
                    'Organisation' => array('id', 'name'),
                    'Role' => array('id', 'name', 'perm_auth', 'perm_site_admin', 'perm_admin')
                )
            ));
            if (!$this->_isSiteAdmin()) {
                foreach ($users as $key => $value) {
                    if ($value['Role']['perm_site_admin']) {
                        $users[$key]['User']['authkey'] = __('Redacted');
                    }
                }
            }
            foreach ($users as $key => $user) {
                unset($users[$key]['User']['totp']);
                if (!empty(Configure::read('Security.advanced_authkeys'))) { // There is no point to show that authkey since it doesn't work when this setting is active
                    unset($users[$key]['User']['authkey']);
                } else if (!$this->_isSiteAdmin() && !empty($user['Role']['perm_admin']) && $user['User']['id'] != $this->Auth->user('id')) {
                    $users[$key]['User']['authkey'] = __('Redacted');
                }
            }
            $users = $this->User->attachIsUserMonitored($users);
            return $this->RestResponse->viewData($users, $this->response->type());
        }

        $this->set('urlparams', $urlParams);
        $this->set('passedArgsArray', $passedArgsArray);
        $this->set('periodic_notifications', $this->User::PERIODIC_NOTIFICATIONS);
        if ($this->_isSiteAdmin()) {
            $users = $this->paginate();
            $users = $this->User->attachIsUserMonitored($users);
        } else {
            $this->paginate['conditions']['AND'][] = ['User.org_id' => $this->Auth->user('org_id')];
            $users = $this->paginate();
            foreach ($users as $key => $value) {
                if ($value['Role']['perm_site_admin']) {
                    $users[$key]['User']['authkey'] = __('Redacted');
                } else if (!empty($value['Role']['perm_admin']) && $value['User']['id'] != $this->Auth->user('id')) {
                    $users[$key]['User']['authkey'] = __('Redacted');
                }
            }
        }
        $this->set('users', $users);
    }

    public function admin_filterUserIndex()
    {
        $passedArgsArray = array();
        $booleanFields = array('autoalert', 'contactalert', 'termsaccepted', 'disabled', 'inactive');
        $textFields = array('role', 'email');
        if (empty(Configure::read('Security.advanced_authkeys'))) {
            $textFields[] = 'authkey';
        }
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
        foreach ($roles as $v) {
            $roleNames[$v['Role']['id']] = $v['Role']['name'];
            $roleJSON[] = array('id' => $v['Role']['id'], 'value' => $v['Role']['name']);
        }
        if ($showOrg) {
            $orgs = $this->User->Organisation->find('list', array(
                'conditions' => array('local' => 1),
                'recursive' => -1,
                'fields' => array('id', 'name'),
                'order' => array('LOWER(name) ASC')
            ));
            $this->set('orgs', $orgs);
        }
        $this->set('roles', $roleNames);
        $this->set('roleJSON', json_encode($roleJSON));
        $rules = $this->_arrayToValuesIndexArray($rules);
        $this->set('rules', $rules);
        $this->set('baseurl', Configure::read('MISP.baseurl'));
        $this->layout = false;
    }

    public function admin_view($id = null)
    {
        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => $this->__adminFetchConditions($id, $edit=False),
            'contain' => [
                'UserSetting',
                'Role',
                'Organisation'
            ]
        ));
        if (empty($user)) {
            throw new NotFoundException(__('Invalid user'));
        }
        if (!empty($user['User']['gpgkey'])) {
            $pgpDetails = $this->User->verifySingleGPG($user);
            $user['User']['pgp_status'] = isset($pgpDetails[2]) ? $pgpDetails[2] : 'OK';
            $user['User']['fingerprint'] = !empty($pgpDetails[4]) ? $pgpDetails[4] : 'N/A';
        }
        $user['User']['orgAdmins'] = $this->User->getOrgAdminsForOrg($user['User']['org_id'], $user['User']['id']);
        if (empty($this->Auth->user('Role')['perm_site_admin']) && !(empty($user['Role']['perm_site_admin']))) {
            $user['User']['authkey'] = __('Redacted');
        }
        if (!empty(Configure::read('Security.advanced_authkeys'))) {
            unset($user['User']['authkey']);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($this->__massageUserObject($user), $this->response->type());
        }
        $this->set('user', $user);

        if (!empty($user['User']['invited_by'])) {
            $invitedBy = $this->User->find('first', [
                'conditions' => array('User.id' => $user['User']['invited_by']),
                'recursive' => -1,
                'fields' => ['id', 'email'],
            ]);
        } else {
            $invitedBy = null;
        }
        $this->set('id', $id);
        $this->set('invitedBy', $invitedBy);
        $this->set('periodic_notifications', $this->User::PERIODIC_NOTIFICATIONS);
        $this->set('admin_view', true);
        $this->render('view');
    }

    public function admin_add()
    {
        $params = null;
        if (!$this->_isSiteAdmin()) {
            $params = array('conditions' => array('perm_site_admin !=' => 1, 'perm_sync !=' => 1, 'perm_regexp_access !=' => 1, 'restricted_to_site_admin' => 0));
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
                    $set_field_via_other_means = false;
                    if (empty($this->request->data['User'][$field])) {
                        if ($field === 'role_id') {
                            if (!empty($default_role_id)) {
                                $this->request->data['User'][$field] = $default_role_id;
                                $set_field_via_other_means = true;
                            }
                        }
                        if (!$set_field_via_other_means) {
                            return $this->RestResponse->saveFailResponse('Users', 'admin_add', false, array($field => 'Mandatory field not set.'), $this->response->type());
                        }
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
                    'autoalert' => $this->User->defaultPublishAlert(),
                    'contactalert' => 0,
                    'disabled' => 0,
                    'newsread' => 0,
                    'change_pw' => 1,
                    'termsaccepted' => 0,
                    'org_id' => $this->Auth->user('org_id'),
                );
                foreach ($defaults as $key => $value) {
                    if (!isset($this->request->data['User'][$key])) {
                        $this->request->data['User'][$key] = $value;
                    }
                }
            }
            $this->request->data['User']['date_created'] = time();
            $this->request->data['User']['last_pw_change'] = $this->request->data['User']['date_created'];
            if (!array_key_exists($this->request->data['User']['role_id'], $syncRoles)) {
                $this->request->data['User']['server_id'] = 0;
            }
            $this->User->create();
            // set invited by
            $chosenRole = $this->User->Role->find('first', [
                'conditions' => ['id' => $this->request->data['User']['role_id']],
            ]);
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
            if (Configure::read('CustomAuth_enable') && Configure::read('CustomAuth_required')) {
                $this->request->data['User']['change_pw'] = 0;
            }
            $this->request->data['User']['newsread'] = 0;
            if (!$this->_isSiteAdmin()) {
                $this->request->data['User']['org_id'] = $this->Auth->user('org_id');
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
                    if ($fail) {
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
                    $fieldList = array('password', 'email', 'external_auth_required', 'external_auth_key', 'enable_password', 'confirm_password', 'org_id', 'role_id', 'authkey', 'nids_sid', 'server_id', 'gpgkey', 'certif_public', 'autoalert', 'contactalert', 'disabled', 'invited_by', 'change_pw', 'termsaccepted', 'newsread', 'date_created', 'date_modified', 'last_pw_change');
                    if ($this->User->save($this->request->data, true, $fieldList)) {
                        $notification_message = '';
                        if (!empty($this->request->data['User']['notify'])) {
                            $user = $this->User->find('first', array('conditions' => array('User.id' => $this->User->id), 'recursive' => -1));
                            $password = isset($this->request->data['User']['password']) ? $this->request->data['User']['password'] : false;
                            $result = $this->User->initiatePasswordReset($user, true, true, $password);
                            if ($result && empty(Configure::read('MISP.disable_emailing'))) {
                                $notification_message .= ' ' . __('User notified of new credentials.');
                            } else {
                                $notification_message .= ' ' . __('User notification of new credentials could not be send.');
                            }
                        }
                        if (!empty(Configure::read('Security.advanced_authkeys')) && $this->_isRest()) {
                            $this->loadModel('AuthKey');
                            $newKey = $this->AuthKey->createnewkey($this->User->id);
                        }
                        if ($this->_isRest()) {
                            $user = $this->User->find('first', array(
                                    'conditions' => array('User.id' => $this->User->id),
                                    'recursive' => -1
                            ));
                            $user['User']['password'] = '******';
                            if (!empty(Configure::read('Security.advanced_authkeys'))) {
                                $user['User']['authkey'] = $newKey;
                            }
                            return $this->RestResponse->viewData($user, $this->response->type());
                        } else {
                            $this->Flash->success(__('The user has been saved.') . $notification_message);
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
            $this->set(compact('roles', 'syncRoles'));
            $this->set('canFetchPgpKey', $this->__canFetchPgpKey());
        }
    }

    public function admin_edit($id = null)
    {
        $this->set('currentOrg', $this->Auth->user('org_id'));
        $this->User->id = $id;
        $params = array();
        $allowedRole = '';

        $userToEdit = $this->User->find('first', array(
            'conditions' => $this->__adminFetchConditions($id),
            'recursive' => -1,
            'fields' => array('User.id', 'User.role_id', 'User.email', 'User.org_id', 'Role.perm_site_admin'),
            'contain' => array('Role')
        ));
        if (empty($userToEdit)) {
            throw new NotFoundException(__('Invalid user'));
        }
        if (!$this->_isSiteAdmin()) {
            // Org admins should be able to select the role that is already assigned to an org user when editing them.
            // What happened previously:
            // Org admin edits another org admin of the same org
            // Org admin is not allowed to set privileged access roles (site_admin/sync/regex)
            // MISP automatically chooses the first available option for the user as the selected setting (usually user)
            // Org admin is downgraded to a user
            // Now we make an exception for the already assigned role, both in the form and the actual edit.
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
            if (!$this->_isRest() || empty($this->request->header('Authorization'))) {
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
            if (!$this->_isSiteAdmin() && !$abortPost) {
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
                $fields = [];
                $blockedFields = array('id', 'invited_by', 'date_modified');
                if (!$this->_isSiteAdmin()) {
                    $blockedFields[] = 'org_id';
                }
                if (!$this->__canChangeLogin()) {
                    $blockedFields[] = 'email';
                }
                if (!$this->__canChangePassword()) {
                    $blockedFields[] = 'enable_password';
                    $blockedFields[] = 'change_pw';
                }
                foreach (array_keys($this->request->data['User']) as $field) {
                    if (in_array($field, $blockedFields)) {
                        continue;
                    }
                    if ($field != 'password') {
                        $fields[] = $field;
                    }
                }
                if (
                    (!empty($this->request->data['User']['enable_password']) || $this->_isRest()) &&
                    !empty($this->request->data['User']['password']) &&
                    $this->__canChangePassword()
                ) {
                    $fields[] = 'password';
                    $fields[] = 'last_pw_change';
                    $this->request->data['User']['last_pw_change'] = time();
                    if ($this->_isRest() && !isset($this->request->data['User']['confirm_password'])) {
                        $this->request->data['User']['confirm_password'] = $this->request->data['User']['password'];
                        $fields[] = 'confirm_password';
                    }
                }
                if (!$this->_isRest()) {
                    $fields[] = 'role_id';
                }
                if (!$this->_isSiteAdmin() && isset($this->request->data['User']['role_id'])) {
                    $chosenRole = $this->User->Role->find('first', [
                        'conditions' => ['id' => $this->request->data['User']['role_id']],
                    ]);
                    if (
                        empty($chosenRole) ||
                        (
                            ($chosenRole['Role']['id'] != $allowedRole) &&
                            ($chosenRole['Role']['perm_site_admin'] == 1 ||
                            $chosenRole['Role']['perm_regexp_access'] == 1 ||
                            $chosenRole['Role']['perm_sync'] == 1) ||
                            $chosenRole['Role']['restricted_to_site_admin'] == 1
                        )
                    ) {
                        throw new Exception('You are not authorised to assign that role to a user.');
                    }
                }
                $fields[] = 'date_modified'; // time will be inserted in `beforeSave` action

                $fieldsOldValues = $this->User->find('first', [
                    'recursive' => -1,
                    'conditions' => ['id' => $id],
                ])['User'];

                if ($this->User->save($this->request->data, true, $fields)) {
                    // newValues to array
                    $fieldsNewValues = array();
                    foreach ($fields as $field) {
                        if ($field === 'date_modified') {
                            continue;
                        }
                        if ($field !== 'confirm_password') {
                            $newValue = $this->data['User'][$field];
                            if (is_array($newValue)) {
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
                                $fieldsNewValues[$field] = $newValueStr;
                            } else {
                                $fieldsNewValues[$field] = $newValue;
                            }
                        } else {
                            $fieldsNewValues[$field] = $this->data['User']['password'];
                        }
                    }
                    // compare
                    $fieldsResult = array();
                    foreach ($fields as $field) {
                        if ($field === 'date_modified') {
                            continue;
                        }
                        if (isset($fieldsOldValues[$field]) && $fieldsOldValues[$field] != $fieldsNewValues[$field]) {
                            if ($field != 'confirm_password' && $field != 'enable_password') {
                                $fieldsResult[$field] = array($fieldsOldValues[$field], $fieldsNewValues[$field]);
                            }
                        }
                    }
                    $user = $this->User->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('User.id' => $this->User->id)
                    ));
                    $this->User->extralog($this->Auth->user(), "edit", "user", $fieldsResult, $user);
                    if ($this->_isRest()) {
                        $user['User']['password'] = '******';
                        if (!empty(Configure::read('Security.advanced_authkeys'))) {
                            unset($user['User']['authkey']);
                        }
                        return $this->RestResponse->viewData($user, $this->response->type());
                    } else {
                        $this->Flash->success(__('The user has been saved'));
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
        $this->set(compact('roles', 'syncRoles'));
        $this->set('canChangeLogin', $this->__canChangeLogin());
        $this->set('canChangePassword', $this->__canChangePassword());
        $this->set('canFetchPgpKey', $this->__canFetchPgpKey());
    }

    public function admin_delete($id = null)
    {
        if ($this->request->is('post') || $this->request->is('delete')) {
            $user = $this->User->find('first', array(
                'conditions' => $this->__adminFetchConditions($id),
                'recursive' => -1,
                'contain' => array('Role')
            ));
            if (empty($user)) {
                throw new NotFoundException(__('Invalid user'));
            }
            if ($this->User->delete($id)) {
                $fieldsDescrStr = 'User (' . $id . '): ' . $user['User']['email'];
                $this->User->extralog($this->Auth->user(), "delete", $fieldsDescrStr, '');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('User', 'admin_delete', $id, $this->response->type(), 'User deleted.');
                } else {
                    $this->Flash->success(__('User deleted'));
                    $this->redirect(array('action' => 'index'));
                }
            }
            $this->Flash->error(__('User was not deleted'));
            $this->redirect(array('action' => 'index'));
        } else {
            $this->set(
                'question',
                __('Are you sure you want to delete the user? It is highly recommended to never delete users but to disable them instead.')
            );
            $this->set('title', __('Delete user'));
            $this->set('actionName', 'Delete');
            $this->render('/genericTemplates/confirm');
        }
    }

    public function admin_massToggleField($fieldName, $enabled)
    {
        if (!in_array($fieldName, ['disabled', 'autoalert'], true)) {
            throw new MethodNotAllowedException(__('The field `%s` cannot be toggled', $fieldName));
        }
        if ($this->request->is(['post', 'put'])) {
            $jsonIds = $this->request->data['User']['user_ids'];
            $ids = $this->_jsonDecode($jsonIds);
            $users = $this->User->find('all', [
                'conditions' => $this->__adminFetchConditions($ids),
                'recursive' => -1,
                'fields' => ['id', $fieldName],
                'contain' => array('Role')
            ]);
            if (empty($users)) {
                throw new NotFoundException(__('Invalid users'));
            }
            $count = 0;
            foreach ($users as $user) {
                if ($user['User'][$fieldName] != $enabled) {
                    $this->User->updateField($user['User'], $fieldName, $enabled);
                    $count++;
                }
            }
            if ($count > 0) {
                $message = __('%s users got their field `%s` %s', $count, $fieldName, $enabled ? __('enabled') : __('disabled'));
            } else {
                $message = __('All users have already their field `%s` %s', $fieldName, $enabled ? __('enabled') : __('disabled'));
            }
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('User', 'admin_massToggleField', 'selected', $this->response->type(), $message);
            } else {
                if ($count > 0) {
                    $this->Flash->success($message);
                } else {
                    $this->Flash->info($message);
                }
                $this->redirect('/admin/users/index');
            }
        }
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
        $oldHash = false;
        if ($this->request->is(['post', 'put'])) {
            $this->Bruteforce = ClassRegistry::init('Bruteforce');
            if (!empty($this->request->data['User']['email'])) {
                if ($this->Bruteforce->isBlocklisted($this->request->data['User']['email'])) {
                    $expire = Configure::check('SecureAuth.expire') ? Configure::read('SecureAuth.expire') : 300;
                    throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait ' . $expire . ' seconds and try again.');
                }
            }
            $unauth_user = $this->User->find('first', [
                'conditions' => ['User.email' => $this->request->data['User']['email']],
                'fields' => ['User.password', 'User.totp', 'User.hotp_counter'],
                'recursive' => -1,
            ]);
            if ($unauth_user) {
                // Check the length of the user's authkey match old format. This can be removed in future.
                $userPass = $unauth_user['User']['password'];
                if (!empty($userPass) && strlen($userPass) === 40) {
                    $oldHash = true;
                    unset($this->Auth->authenticate['Form']['passwordHasher']); // use default password hasher
                    $this->Auth->constructAuthenticate();
                }
                // user has TOTP token, check creds and redirect to TOTP validation
                if (!Configure::read('Security.otp_disabled')) {
                    if (!empty($unauth_user['User']['totp']) && !$unauth_user['User']['disabled'] && class_exists('\OTPHP\TOTP')) {
                        $user = $this->Auth->identify($this->request, $this->response);
                        if ($user && !$user['disabled']) {
                            $this->Session->write('otp_user', $user);
                            return $this->redirect('otp');
                        }
                    }
                }
            }
        }
        // if instance requires email OTP
        if ($this->request->is('post') && Configure::read('Security.email_otp_enabled')) {
            $user = $this->Auth->identify($this->request, $this->response);
            if ($user && !$user['disabled']) {
              $this->Session->write('email_otp_user', $user);
              return $this->redirect('email_otp');
            }
        }
        $formLoginEnabled = isset($this->Auth->authenticate['Form']);
        $this->set('formLoginEnabled', $formLoginEnabled);

        if ($this->Auth->login()) {
            if ($oldHash) {
                // Convert old style password hash to blowfish
                $passwordToSave = $this->request->data['User']['password'];
                // Password is converted to hashed form automatically
                $this->User->save(['id' => $this->Auth->user('id'), 'password' => $passwordToSave], false, ['password']);
            }
            // login was successful, do everything that is needed such as logging and more:
            $this->_postlogin();
        } else {
            // don't display authError before first login attempt
            if (str_replace("//", "/", $this->webroot . $this->Session->read('Auth.redirect')) == $this->webroot && $this->Session->read('Message.auth.message') == $this->Auth->authError) {
                $this->Session->delete('Message.auth');
            }
            // Login was failed, do everything that is needed such as blocklisting, logging and more
            // Also don't display "invalid user" before first login attempt
            if ($this->request->is('post') || $this->request->is('put')) {
                $this->Flash->error(__('Invalid username or password, try again'));
                if (isset($this->request->data['User']['email'])) {
                    // increase bruteforce attempt and log
                    $this->Bruteforce->insert($this->request->data['User']['email']);
                }
            }

            $this->User->init();
        }
    }

    private function _postlogin()
    {
        $authUser = $this->Auth->user();
        $this->User->extralog($authUser, "login");

        $this->User->Behaviors->disable('SysLogLogable.SysLogLogable');
        $user = $this->User->find('first', array(
            'conditions' => array(
                'User.id' => $authUser['id'],
            ),
            'fields' => ['User.id', 'User.current_login', 'User.last_login'],
            'recursive' => -1
        ));
        // update login timestamp and welcome user
        $this->User->updateLoginTimes($user['User']);
        $this->User->Behaviors->enable('SysLogLogable.SysLogLogable');

        $lastUserLogin = $user['User']['last_login'];
        if ($lastUserLogin) {
            $readableDatetime = (new DateTime())->setTimestamp($lastUserLogin)->format('D, d M y H:i:s O'); // RFC822
            $this->Flash->info(__('Welcome! Last login was on %s', $readableDatetime));
        }

        if (Configure::read('Security.alert_on_suspicious_logins')) {
            try {
                // there are reasons to believe there is evil happening, suspicious. Inform user and (org)admins.
                $suspiciousnessReason = $this->User->UserLoginProfile->_isSuspicious();
                if ($suspiciousnessReason) {
                    // raise an alert (the SIEM component should ensure (org)admins are informed)
                    $this->loadModel('Log');
                    $this->Log->createLogEntry($authUser, 'auth_alert', 'User', $authUser['id'], 'Suspicious login.', $suspiciousnessReason);
                    // Line below commented out to NOT inform user/org admin of the suspicious login.
                    // The reason is that we want to prevent other user actions cause trouble.
                    // However this also means we're sitting on data that could be used to detect new evil logins.
                    // As we're generating alerts, the sysadmin should be keeping an eye on these
                    // $this->User->UserLoginProfile->email_suspicious($user, $suspiciousness_reason);
                }
                // verify UserLoginProfile trust status and perform informative actions
                if (!$this->User->UserLoginProfile->_isTrusted()) {
                    // send email to inform the user
                    $this->User->UserLoginProfile->emailNewLogin($authUser);
                }
            } catch (Exception $e) {
                // At first login after code update and before DB schema update we might end up with problems.
                // Just catch it cleanly here to prevent problems.
                $this->log($e->getMessage(), LOG_WARNING);
            }
        }

        // no state changes are ever done via GET requests, so it is safe to return to the original page:
        $this->redirect($this->Auth->redirectUrl());
    }

    public function routeafterlogin()
    {
        // Events list
        $url = $this->Session->consume('pre_login_requested_url');
        if (!empty(Configure::read('MISP.forceHTTPSforPreLoginRequestedURL')) && !empty($url)) {
            if (substr($url, 0, 7) === "http://") {
                $url = sprintf('https://%s', substr($url, 7));
            }
        }
        if (empty($url)) {
            $homepage = $this->User->UserSetting->getValueForUser($this->Auth->user('id'), 'homepage');
            if (!empty($homepage)) {
                $url = $homepage['path'];
            } else {
                $url = array('controller' => 'events', 'action' => 'index');
            }
        }
        $this->redirect($url);
    }

    public function logout()
    {
        if ($this->Session->check('Auth.User')) {
            $this->User->extralog($this->Auth->user(), "logout");
        }
        if (!Configure::read('Plugin.CustomAuth_custom_logout')) {
            $this->Flash->info(__('Good-Bye'));
        }
        $user = $this->User->find('first', array(
            'conditions' => array(
                'User.id' => $this->Auth->user('id')
            ),
            'recursive' => -1
        ));
        unset($user['User']['password']);
        $user['User']['action'] = 'logout';
        $this->User->save($user['User'], true, array('id'));
        $this->Session->write('otp_secret', null);
        $this->redirect($this->Auth->logout());
    }

    public function resetauthkey($id = null, $alert = false)
    {
        if (!$this->request->is('post') && !$this->request->is('put')) {
            throw new MethodNotAllowedException(__('This functionality is only accessible via POST requests.'));
        }
        if ($id === 'me') {
            $id = $this->Auth->user('id');
            // Reset just current auth key
            $keyId = isset($this->Auth->user()['authkey_id']) ? $this->Auth->user()['authkey_id'] : null;
        } else {
            $keyId = null;
        }
        $newkey = $this->User->resetauthkey($this->Auth->user(), $id, $alert, $keyId);
        if ($newkey === false) {
            throw new MethodNotAllowedException(__('Invalid user.'));
        }
        if (!$this->_isRest()) {
            $this->Flash->success(__('New authkey generated.'));
            $this->redirect($this->referer());
        } else {
            return $this->RestResponse->saveSuccessResponse('User', 'resetauthkey', $id, $this->response->type(), 'Authkey updated: ' . $newkey);
        }
    }

    public function resetAllSyncAuthKeys()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This functionality is only accessible via POST requests.'));
        }
        $results = $this->User->resetAllSyncAuthKeysRouter($this->Auth->user());
        if ($results === true) {
            $message = __('Job initiated.');
        } else {
            $message = __('%s authkeys reset, %s could not be reset.', $results['success'], $results['fails']);
        }
        if (!$this->_isRest()) {
            $this->Flash->info($message);
            $this->redirect($this->referer());
        } else {
            return $this->RestResponse->saveSuccessResponse('User', 'resetAllSyncAuthKeys', false, $this->response->type(), $message);
        }
    }

    public function histogram($selected = null)
    {
        $user = $this->_closeSession();
        if ($selected == '[]') {
            $selected = null;
        }
        $selectedTypes = array();
        if ($selected) {
            $selectedTypes = $this->_jsonDecode($selected);
        }
        if (!$this->_isSiteAdmin() && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
            $org_ids = array($user['org_id']);
        } else {
            $org_ids = $this->User->Event->find('column', array(
                'fields' => array('Event.orgc_id'),
                'unique' => true,
            ));
        }
        $orgs_temp = $this->User->Organisation->find('list', array(
            'fields' => array('Organisation.id', 'Organisation.name'),
            'conditions' => array('Organisation.id' => $org_ids)
        ));
        $orgs = array(0 => 'All organisations') + $orgs_temp;
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
            foreach ($temp as $v) {
                $v = (int) $v;
                if ($v > $max) {
                    $max = $v;
                }
                $total += $v;
            }
            $data[$org_id] = [
                'data' => $temp,
                'org_name' => $org_name,
                'total' => $total,
            ];
        }
        uasort($data, function ($a, $b) {
            return $b['total'] - $a['total'];
        });
        $data = array_values($data);

        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        }

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

        $this->set('typeDb', $typeDb);
        $this->set('sigTypes', $sigTypes);
        $this->layout = false;
    }

    public function terms()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->User->updateField($this->Auth->user(), 'termsaccepted', true);
            $this->Flash->success(__('You accepted the Terms and Conditions.'));
            $this->redirect(array('action' => 'routeafterlogin'));
        }

        $termsFile = Configure::read('MISP.terms_file');
        if (empty($termsFile)) {
            throw new NotFoundException(__("MISP Terms and Conditions are not defined"));
        }

        $termsDownload = (bool)Configure::read('MISP.terms_download');
        if (!$termsDownload) {
            $termsFilePath = APP . 'files' . DS . 'terms' . DS .  basename($termsFile);
            try {
                $termsContent = FileAccessTool::readFromFile($termsFilePath);
            } catch (Exception $e) {
                $termsContent = false;
            }
            $this->set("termsContent", $termsContent);
        }

        $this->set("termsDownload", $termsDownload);
        $this->set('termsaccepted', $this->Auth->user('termsaccepted'));
    }

    public function downloadTerms()
    {
        $termsFile = Configure::read('MISP.terms_file');
        if (empty($termsFile)) {
            throw new NotFoundException(__("MISP Terms and Conditions are not defined"));
        }

        $termsFilePath = APP . 'files' . DS . 'terms' . DS . basename($termsFile);
        $this->response->file($termsFilePath, ['download' => true, 'name' => $termsFile]);
        return $this->response;
    }

    public function checkAndCorrectPgps()
    {
        $this->set('fails', $this->User->checkAndCorrectPgps());
    }

    public function admin_quickEmail($user_id)
    {
        $user = $this->User->find('first', array(
            'conditions' => $this->__adminFetchConditions($user_id, $edit=False),
            'recursive' => -1,
            'contain' => array('Role')
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
                $this->Flash->error($error);
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

    public function admin_email($isPreview=false)
    {
        $isPostOrPut = $this->request->is('post') || $this->request->is('put');
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $conditions = array('org_id' => $this->Auth->user('org_id'));
        }

        // harvest parameters
        if ($isPostOrPut) {
            $recipient = $this->request->data['User']['recipient'];
            $recipientEmailList = $this->request->data['User']['recipientEmailList'];
            $orgNameList = $this->request->data['User']['orgNameList'];
        } else {
            $recipient = isset($this->params['named']['recipient']) ? $this->params['named']['recipient'] : null;
            $recipientEmailList = isset($this->params['named']['recipientEmailList']) ? $this->params['named']['recipientEmailList'] : null;
            $orgNameList = isset($this->params['named']['orgNameList']) ? $this->params['named']['orgNameList'] : null;
        }

        if (!is_null($recipient) && $recipient == 0) {
            if (is_null($recipientEmailList)) {
                throw new NotFoundException(__('Recipient email not provided'));
            }
            $conditions['id'] = $recipientEmailList;
        } elseif (!is_null($recipient) && $recipient == 2) {
            if (is_null($orgNameList)) {
                throw new NotFoundException(__('Recipient organisation not provided'));
            }
            $conditions['org_id'] = $orgNameList;
        }
        $conditions['AND'][] = array('User.disabled' => 0);

        // Allow to mimic real form post
        if ($isPreview) {
            $users = $this->User->find('list', array('recursive' => -1, 'order' => array('email ASC'), 'conditions' => $conditions, 'fields' => array('email')));
            $this->set('emails', $users);
            $this->set('emailsCount', count($users));
            $this->render('ajax/emailConfirmTemplate');
        } else {
            $users = $this->User->find('all', array('recursive' => -1, 'order' => array('email ASC'), 'conditions' => $conditions));
            // User has filled in his contact form, send out the email.
            if ($isPostOrPut) {
                $this->request->data['User']['message'] = $this->__replaceEmailVariables($this->request->data['User']['message']);
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
            $temp = $this->User->find('all', array('recursive' => -1, 'fields' => array('id', 'email', 'Organisation.name'), 'order' => array('email ASC'), 'conditions' => $conditions, 'contain' => array('Organisation')));
            $emails = array();
            $orgName = array();
            // save all the emails of the users and set it for the dropdown list in the form
            foreach ($temp as $user) {
                $emails[$user['User']['id']] = $user['User']['email'];
                $orgName[$user['Organisation']['id']] = $user['Organisation']['name'];
            }

            $this->set('users', $temp);
            $this->set('recipientEmail', $emails);
            $this->set('orgName', $orgName);
            $this->set('org', Configure::read('MISP.org'));
            $textsToFetch = array('newUserText', 'passwordResetText');
            $this->loadModel('Server');
            foreach ($textsToFetch as $text) {
                $value = Configure::read('MISP.' . $text);
                if (!$value) {
                    $value = $this->Server->serverSettings['MISP'][$text]['value'];
                }
                $this->set($text, $value);
            }
        }
    }

    public function initiatePasswordReset($id, $firstTime = false)
    {
        $user = $this->User->find('first', array(
            'conditions' => $this->__adminFetchConditions($id),
            'recursive' => -1,
            'contain' => array('Role')
        ));
        if (empty($user)) {
            throw new NotFoundException(__('Invalid user'));
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
            $this->layout = false;
            $this->set('user', $user);
            $this->set('firstTime', $firstTime);
            $this->render('ajax/passwordResetConfirmationForm');
        }
    }

    public function otp()
    {
        $user = $this->Session->read('otp_user');
        if (empty($user)) {
            $this->redirect('login');
        }
        if ($this->request->is('post') && isset($this->request->data['User']['otp'])) {
            $this->Bruteforce = ClassRegistry::init('Bruteforce');
            if ($this->Bruteforce->isBlocklisted($user['email'])) {
                $expire = Configure::check('SecureAuth.expire') ? Configure::read('SecureAuth.expire') : 300;
                throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait ' . $expire . ' seconds and try again.');
            }
            $secret = $user['totp'];
            $totp = \OTPHP\TOTP::create($secret);
            $hotp = \OTPHP\HOTP::create($secret);
            if ($totp->verify(trim($this->request->data['User']['otp']))) {
                // OTP is correct, we login the user with CakePHP
                $this->Auth->login($user);
                $this->_postlogin();
            } elseif (isset($user['hotp_counter']) && $hotp->verify(trim($this->request->data['User']['otp']), $user['hotp_counter'])) {
                // HOTP is correct, update the counter and login
                $this->User->id = $user['id'];
                $this->User->saveField('hotp_counter', $user['hotp_counter']+1);
                $this->Auth->login($user);
                $this->_postlogin();
            } else {
                $this->Flash->error(__("The OTP is incorrect or has expired"));
                $fieldsDescrStr = 'User (' . $user['id'] . '): ' . $user['email']. ' wrong OTP token';
                $this->User->extralog($user, "login_fail", $fieldsDescrStr, '');
                $this->Bruteforce->insert($user['email']);
            }
        }
        // GET Request or wrong OTP, just show the form
        $this->set('totp', $user['totp']? true : false);
        $this->set('hotp_counter', $user['hotp_counter']);
    }

    public function hotp()
    {
        if (!class_exists('\OTPHP\HOTP')) {
            $this->Flash->error(__("The required PHP libraries to support OTP are not installed. Please contact your administrator to address this."));
            $this->redirect($this->referer());
        }

        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => array('User.id' => $this->Auth->user('id')),
            'fields' => array(
                'totp', 'email', 'id', 'hotp_counter'
            )
        ));
        $hotp = \OTPHP\HOTP::create($user['User']['totp'], $user['User']['hotp_counter']);
        $hotp_codes = [];
        for ($i=$user['User']['hotp_counter']; $i < $user['User']['hotp_counter']+50 ; $i++) {
            $hotp_codes[$i] = $hotp->at($i);
        }
        $this->set('hotp_codes', $hotp_codes);
    }

    public function totp_new()
    {
        if (Configure::read('LinOTPAuth.enabled')) {
            $this->Flash->error(__("LinOTP is enabled for this instance. Built-in TOTP should not be used."));
            $this->redirect($this->referer());
        }
        if (!class_exists('\OTPHP\TOTP') || !class_exists('\BaconQrCode\Writer')) {
            $this->Flash->error(__("The required PHP libraries to support TOTP are not installed. Please contact your administrator to address this."));
            $this->redirect($this->referer());
        }

        // only allow the users themselves to generate a TOTP secret.
        // If TOTP is enforced they will be invited to generate it at first login
        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => array('User.id' => $this->Auth->user('id')),
            'fields' => array(
                'totp', 'email', 'id'
            )
        ));
        if (empty($user)) {
            throw new NotFoundException(__('Invalid user'));
        }
        // do not allow this page to be accessed if the current already has a TOTP. Just redirect to the users details page with a Flash->error()
        if ($user['User']['totp']) {
            $this->Flash->error(__("Your account already has a TOTP. Please contact your organisational administrator to change or delete it."));
            $this->redirect($this->referer());
        }

        if ($this->request->is('get')) {
            $totp = \OTPHP\TOTP::create();
            $secret = $totp->getSecret();
            $this->Session->write('otp_secret', $secret);  // Store in session, we want to create a new secret each time the totp_new() function is queried via a GET (this will not impede incorrect confirmation attempty)
        } else {
            $secret = $this->Session->read('otp_secret');  // Reload secret from session.
            if ($secret) {
                $totp = \OTPHP\TOTP::create($secret);
            } else {
                $totp = \OTPHP\TOTP::create();
                $secret = $totp->getSecret();
                $this->Session->write('otp_secret', $secret); // Store in session, we want to keep reusing the same QR code until the user correctly enters the generated key on their authenticator
            }
        }
        if ($this->request->is('post') && isset($this->request->data['User']['otp'])) {
            if ($totp->verify(trim($this->request->data['User']['otp']))) {
                // we know the user can generate TOTP tokens, save the new TOTP to the database
                $this->User->id = $user['User']['id'];
                $this->User->saveField('totp', $secret);
                $this->User->saveField('hotp_counter', 0);
                $this->_refreshAuth();
                $this->Flash->info(__('The OTP is correct and now active for your account.'));
                $fieldsDescrStr = 'User (' . $user['User']['id'] . '): ' . $user['User']['email']. ' TOTP token created';
                $this->User->extralog($this->Auth->user(), "update", $fieldsDescrStr, '');
                // redirect to a page that gives the next 50 HOTP
                $this->redirect(array('controller' => 'users', 'action'=> 'hotp'));
            } else {
                $this->Flash->error(__("The OTP is incorrect or has expired."));
            }
        } else {
            // GET Request, just show the form
        }
        // generate QR code with the secret
        $renderer = new \BaconQrCode\Renderer\ImageRenderer(
            new \BaconQrCode\Renderer\RendererStyle\RendererStyle(200),
            new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
        );
        $writer = new \BaconQrCode\Writer($renderer);
        $totp->setLabel($user['User']['email']);
        if (Configure::read('Security.otp_issuer')) {
            $totp->setIssuer(Configure::read('Security.otp_issuer'));
        } else {
            $totp->setIssuer(Configure::read('MISP.org') . ' MISP');
        }
        $qrcode = $writer->writeString($totp->getProvisioningUri());
        $qrcode = preg_replace('/^.+\n/', '', $qrcode); // ignore first <?xml version line

        $this->set('qrcode', $qrcode);
        $this->set('secret', $secret);
    }

    public function totp_delete($id)
    {
        if ($this->request->is(['post', 'delete'])) {
            $user = $this->User->find('first', array(
                'conditions' => $this->__adminFetchConditions($id),
                'recursive' => -1,
                'contain' => array('Role')
            ));
            if (empty($user)) {
                throw new NotFoundException(__('Invalid user'));
            }
            $this->User->id = $id;
            if ($this->User->saveField('totp', null)) {
                $fieldsDescrStr = 'User (' . $id . '): ' . $user['User']['email'] . ' TOTP deleted';
                $this->User->extralog($this->Auth->user(), "update", $fieldsDescrStr, '');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('User', 'totp_delete', $id, $this->response->type(), 'User TOTP deleted.');
                } else {
                    $this->Flash->success(__('User TOTP deleted'));
                    $this->redirect('/admin/users/index');
                }
            }
            $this->Flash->error(__('User TOTP was not deleted'));
            $this->redirect('/admin/users/index');
        } else {
            $this->set(
                'question',
                __('Are you sure you want to delete the TOTP of the user?.')
            );
            $this->set('title', __('Delete user TOTP'));
            $this->set('actionName', 'Delete');
            $this->render('/genericTemplates/confirm');
        }
    }

    public function email_otp()
    {
        $user = $this->Session->read('email_otp_user');
        if (empty($user)) {
            $this->redirect('login');
        }
        $redis = RedisTool::init();
        $user_id = $user['id'];

        if ($this->request->is('post') && isset($this->request->data['User']['otp'])) {
            $stored_otp = $redis->get('misp:otp:' . $user_id);
            if (!empty($stored_otp) && trim($this->request->data['User']['otp']) == $stored_otp) {
                // we invalidate the previously generated OTP
                $redis->del('misp:otp:' . $user_id);
                // We login the user with CakePHP
                $this->Auth->login($user);
                $this->_postlogin();
            } else {
                $this->Flash->error(__("The OTP is incorrect or has expired"));
                $fieldsDescrStr = 'User (' . $user['id'] . '): ' . $user['email']. ' wrong email OTP token';
                $this->User->extralog($user, "login_fail", $fieldsDescrStr, '');
            }
        } else {
            // GET Request

            // We check for exceptions
            $exception_list = Configure::read('Security.email_otp_exceptions');
            if (!empty($exception_list)) {
                $exceptions = explode(",", $exception_list);
                foreach ($exceptions as $exception) {
                    if ($user['email'] === trim($exception)) {
                        // We login the user with CakePHP
                        $this->Auth->login($user);
                        $this->_postlogin();
                    }
                }
            }
            $this->loadModel('Server');

            // Generating the OTP
            $digits = Configure::read('Security.email_otp_length') ?: $this->Server->serverSettings['Security']['email_otp_length']['value'];
            $otp = "";
            for ($i = 0; $i < $digits; $i++) {
                $otp .= random_int(0, 9);
            }
            // We use Redis to cache the OTP
            $redis->set('misp:otp:' . $user_id, $otp);
            $validity = Configure::read('Security.email_otp_validity') ?: $this->Server->serverSettings['Security']['email_otp_validity']['value'];
            $redis->expire('misp:otp:' . $user_id, (int)$validity * 60);

            // Email construction
            $body = Configure::read('Security.email_otp_text') ?: $this->Server->serverSettings['Security']['email_otp_text']['value'];
            $body = $this->__replaceEmailVariables($body);
            $body = str_replace('$validity', $validity, $body);
            $body = str_replace('$otp', $otp, $body);
            $body = str_replace('$ip', $this->_remoteIp(), $body);
            $body = str_replace('$username', $user['email'], $body);

            // Fetch user that contains also PGP or S/MIME keys for e-mail encryption
            $userForSendMail = $this->User->getUserById($user_id);
            $body = str_replace('\n', PHP_EOL, $body);
            $result = $this->User->sendEmail($userForSendMail, $body, false, "[" . Configure::read('MISP.org') . " MISP] Email OTP");

            if ($result) {
                $this->Flash->success(__("An email containing a OTP has been sent."));
            } else {
                $this->Flash->error(__("The email couldn't be sent, please reach out to your administrator."));
            }
        }
    }

    // shows some statistics about the instance
    public function statistics($page = 'data')
    {
        $user = $this->_closeSession(true); // loading this page can take long time, so we can close session

        if (!$this->_isRest()) {
            $pages = [
                'data' => __('Usage data'),
                'orgs' => __('Organisations'),
                'users' => __('User and Organisation statistics'),
                'tags' => __('Tags'),
                'attributehistogram' => __('Attribute histogram'),
                'sightings' => __('Sightings toplists'),
                'galaxyMatrix' => __('Galaxy Matrix')
            ];
            if (!$this->_isSiteAdmin() && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
                unset($pages['orgs']);
            }

            $this->set('page', $page);
            $this->set('pages', $pages);
        }

        if ($page === 'data') {
            $result = $this->__statisticsData($user, $this->params['named']);
        } elseif ($page === 'orgs') {
            if (!$this->_isSiteAdmin() && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
                throw new MethodNotAllowedException('This feature is currently disabled.');
            }
            $result = $this->__statisticsOrgs($this->params['named']);
        } elseif ($page === 'users') {
            $result = $this->__statisticsUsers($this->params['named']);
        } elseif ($page === 'tags') {
            $result = $this->__statisticsTags($this->params['named']);
        } elseif ($page === 'attributehistogram') {
            if ($this->_isRest()) {
                return $this->histogram($selected = null);
            } else {
                $this->render('statistics_histogram');
            }
        } elseif ($page === 'sightings') {
            $result = $this->__statisticsSightings($user, $this->params['named']);
        } elseif ($page === 'galaxyMatrix') {
            $result = $this->__statisticsGalaxyMatrix($user, $this->params['named']);
        } else {
            throw new NotFoundException("Invalid page");
        }

        if ($this->_isRest()) {
            return $result;
        }
    }

    private function __statisticsData(array $user, $params = array())
    {
        // set all of the data up for the heatmaps
        $params = array(
            'fields' => array('id', 'name'),
            'recursive' => -1,
            'order' => ['name'],
        );
        if (!$user['Role']['perm_site_admin'] && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
            $params['conditions'] = array('Organisation.id' => $user['org_id']);
        }
        $orgs = $this->User->Organisation->find('list', $params);

        $local_orgs_params = $params;
        $local_orgs_params['conditions']['Organisation.local'] = 1;
        $local_orgs_count = $this->User->Organisation->find('count', $local_orgs_params);

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
        $stats['attributes_per_event'] = $stats['event_count'] != 0 ? round($stats['attribute_count'] / $stats['event_count']) : 0;

        $stats['correlation_count'] = $this->User->Event->Attribute->Correlation->find('count', array('recursive' => -1));

        $stats['proposal_count'] = $this->User->Event->ShadowAttribute->find('count', array('recursive' => -1, 'conditions' => array('deleted' => 0)));

        $stats['user_count'] = $this->User->find('count', array('recursive' => -1));
        $stats['user_count_pgp'] = $this->User->find('count', array('recursive' => -1, 'conditions' => array('User.gpgkey !=' => '')));
        $stats['org_count'] = count($orgs);
        $stats['local_org_count'] = $local_orgs_count;
        $stats['contributing_org_count'] = $this->User->Event->find('count', array('recursive' => -1, 'group' => array('Event.orgc_id')));
        $stats['average_user_per_org'] = $stats['local_org_count'] != 0 ?  round($stats['user_count'] / $stats['local_org_count'], 1) : 0;

        $this->loadModel('Thread');
        $stats['thread_count'] = $this->Thread->find('count', array('conditions' => array('Thread.post_count >' => 0), 'recursive' => -1));
        $stats['thread_count_month'] = $this->Thread->find('count', array('conditions' => array('Thread.date_created >' => date("Y-m-d H:i:s", $this_month), 'Thread.post_count >' => 0), 'recursive' => -1));

        $stats['post_count'] = $this->Thread->Post->find('count', array('recursive' => -1));
        $stats['post_count_month'] = $this->Thread->Post->find('count', array('conditions' => array('Post.date_created >' => date("Y-m-d H:i:s", $this_month)), 'recursive' => -1));
        foreach ($stats as &$value) {
            $value = strval($value);
        }
        if ($this->_isRest()) {

            $data = array(
                'stats' => $stats
            );
            return $this->RestResponse->viewData($data, $this->response->type());
        }

        $this->set('stats', $stats);
        $this->set('orgs', $orgs);
        $this->set('start', strtotime(date('Y-m-d H:i:s') . ' -5 months'));
        $this->set('end', strtotime(date('Y-m-d H:i:s')));
        $this->set('startDateCal', $year . ', ' . $month . ', 01');
        $range = '[5, 10, 50, 100]';
        $this->set('range', $range);
        $this->set('activityUrl', $this->baseurl . (Configure::read('MISP.log_new_audit') ? '/audit_logs' : '/logs') . '/returnDates');
        $this->render('statistics_data');
    }

    private function __statisticsSightings(array $user, $params = array())
    {
        $this->loadModel('Sighting');
        $conditions = ['Sighting.org_id' => $user['org_id']];
        if (isset($params['timestamp'])) {
            $conditions['Sighting.date_sighting >'] = $params['timestamp'];
        }
        $sightings = $this->Sighting->find('all', array(
            'conditions' => $conditions,
            'fields' => ['Sighting.type', 'Sighting.source', 'Sighting.event_id'],
        ));
        $data = array();
        $toplist = array();
        $eventids = array();
        foreach ($sightings as $v) {
            if ($v['Sighting']['source'] == '') {
                $v['Sighting']['source'] = 'Undefined';
            }
            $type = array('sighting', 'false-positive', 'expiration')[$v['Sighting']['type']];
            if (isset($data[$v['Sighting']['source']][$type])) {
                $data[$v['Sighting']['source']][$type]++;
            } else {
                $data[$v['Sighting']['source']][$type] = 1;
            }
            if (!isset($toplist[$v['Sighting']['source']])) {
                $toplist[$v['Sighting']['source']] = 1;
            } else {
                $toplist[$v['Sighting']['source']]++;
            }
            if (!isset($eventids[$v['Sighting']['source']][$type])) {
                $eventids[$v['Sighting']['source']][$type] = [];
            }
            if (!in_array($v['Sighting']['event_id'], $eventids[$v['Sighting']['source']][$type])) {
                $eventids[$v['Sighting']['source']][$v['Sighting']['type']][] = $type;
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
        $conditions = array();
        if (!isset($params['scope']) || $params['scope'] == 'local') {
            $params['scope'] = 'local';
            $conditions['Organisation.local'] = 1;
        } elseif ($params['scope'] == 'external') {
            $conditions['Organisation.local'] = 0;
        }
        $orgs = $this->User->Organisation->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => array('id', 'name', 'description', 'local', 'contacts', 'type', 'sector', 'nationality'),
        ));
        $orgs = array_column(array_column($orgs, 'Organisation'), null, 'id');
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
            'fields' => array('Event.orgc_id', 'count(*)', 'sum(Event.attribute_count) as attributeCount')
        ));
        foreach ($events as $event) {
            $orgs[$event['Event']['orgc_id']]['eventCount'] = $event[0]['count(*)'];
            $orgs[$event['Event']['orgc_id']]['attributeCount'] = $event[0]['attributeCount'];
            $orgs[$event['Event']['orgc_id']]['orgActivity'] = $this->User->getOrgActivity($event['Event']['orgc_id'], array('event_timestamp' => '365d'));
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
        $this->_closeSession();
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
        $taxonomies = array_merge(array('custom'), $taxonomies);
        if ($this->_isRest()) {
            $data = array(
                'flatData' => $flatData,
                'treemap' => $treemap
            );
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->set('taxonomies', $taxonomies);
            $this->set('flatData', $flatData);
            $this->set('treemap', $treemap);
            $this->set('tags', $tags);
            $this->layout = false;
            $this->render('ajax/tag_statistics_graph');
        }
    }

    private function __statisticsTags($params = array())
    {
        if ($this->_isRest()) {
            return $this->tagStatisticsGraph();
        } else {
            $this->render('statistics_tags');
        }
    }

    private function __statisticsGalaxyMatrix(array $user, $params = array())
    {
        $this->loadModel('Galaxy');
        $mitre_galaxy_id = $this->Galaxy->getMitreAttackGalaxyId();
        $galaxy_id = $params['galaxy_id'] ?? $mitre_galaxy_id;

        $organisations = $this->User->Organisation->find('list', array(
            'conditions' => $this->User->Organisation->createConditions($user),
            'recursive' => -1,
            'fields' => ['id', 'name'],
        ));
        $organisations = [0 => __('All')] + $organisations;
        $this->set('organisations', $organisations);

        if (isset($params['organisation']) && $params['organisation'] != 0) {
            if (isset($organisations[$params['organisation']])) {
                $this->set('picked_organisation_id', $params['organisation']);
            } else {
                throw new NotFoundException(__("Invalid organisation"));
            }
        } else {
            $this->set('picked_organisation_id', -1);
        }

        $rest_response_empty = true;
        $ignore_score = false;
        if (
            isset($params['dateFrom'])
            || isset($params['dateTo'])
            || isset($params['organisation']) && $params['organisation'] != 0
        ) { // use restSearch
            $ignore_score = true;
            $filters = array();
            if (isset($params['dateFrom'])) {
                $filters['from'] = $params['dateFrom'];
                $this->set('dateFrom', $params['dateFrom']);
            }
            if (isset($params['dateTo'])) {
                $filters['to'] = $params['dateTo'];
                $this->set('dateTo', $params['dateTo']);
            }
            if (isset($params['organisation'])) {
                $filters['org'] = $params['organisation'];
            }
            $elementCounter = 0;
            $renderView = '';
            $final = $this->User->Event->restSearch($user, 'attack', $filters, false, false, $elementCounter, $renderView);
            $final = JsonTool::decode($final);
            if (!empty($final)) {
                $rest_response_empty = false;
                foreach ($final as $key => $data) {
                    $this->set($key, $data);
                }
            }
        }

        // No need for restSearch or result is empty
        if ($rest_response_empty) {
            $matrixData = $this->Galaxy->getMatrix($galaxy_id);
            $tabs = $matrixData['tabs'];
            $matrixTags = $matrixData['matrixTags'];
            $killChainOrders = $matrixData['killChain'];
            $instanceUUID = $matrixData['instance-uuid'];
            if ($ignore_score) {
                $scores_uniform = array('scores' => array(), 'maxScore' => 0);
            } else {
                $scores_uniform = $this->User->Event->EventTag->getTagScoresUniform(0, $matrixTags);
            }
            $scores = $scores_uniform['scores'];
            $maxScore = $scores_uniform['maxScore'];
            // FIXME: temporary fix: add the score of deprecated mitre galaxies to the new one (for the stats)
            if ($matrixData['galaxy']['id'] == $mitre_galaxy_id) {
                $mergedScore = array();
                foreach ($scores as $tag => $v) {
                    $predicateValue = explode(':', $tag, 2)[1];
                    $predicateValue = explode('=', $predicateValue, 2);
                    $predicate = $predicateValue[0];
                    $clusterValue = $predicateValue[1];
                    $mappedTag = '';
                    $mappingWithoutExternalId = array();
                    if ($predicate == 'mitre-attack-pattern') {
                        $mappedTag = $tag;
                        $name = explode(" ", $tag);
                        $name = implode(" ", array_slice($name, 0, -2)); // remove " - external_id"
                        $mappingWithoutExternalId[$name] = $tag;
                    } else {
                        $name = explode(" ", $clusterValue);
                        $name = implode(" ", array_slice($name, 0, -2)); // remove " - external_id"
                        if (isset($mappingWithoutExternalId[$name])) {
                            $mappedTag = $mappingWithoutExternalId[$name];
                        } else {
                            $adjustedTagName = $this->Galaxy->GalaxyCluster->find('list', array(
                                'group' => array('GalaxyCluster.id', 'GalaxyCluster.tag_name'),
                                'conditions' => array('GalaxyCluster.tag_name LIKE' => 'misp-galaxy:mitre-attack-pattern=' . $name . '% T%'),
                                'fields' => array('GalaxyCluster.tag_name')
                            ));
                            if (!empty($adjustedTagName)) {
                                $adjustedTagName = array_values($adjustedTagName)[0];
                                $mappingWithoutExternalId[$name] = $adjustedTagName;
                                $mappedTag = $mappingWithoutExternalId[$name];
                            }
                        }
                    }
                    if (isset($mergedScore[$mappedTag])) {
                        $mergedScore[$mappedTag] += $v;
                    } else {
                        $mergedScore[$mappedTag] = $v;
                    }
                }
                $scores = $mergedScore;
                $maxScore = !empty($mergedScore) ? max(array_values($mergedScore)) : 0;
            }
            // end FIXME

            $this->Galaxy->sortMatrixByScore($tabs, $scores);
            if ($this->_isRest()) {
                $json = array('matrix' => $tabs, 'scores' => $scores, 'instance-uuid' => $instanceUUID);
                return $this->RestResponse->viewData($json, $this->response->type());
            }
            App::uses('ColourGradientTool', 'Tools');
            $gradientTool = new ColourGradientTool();
            $colours = $gradientTool->createGradientFromValues($scores);

            $this->set('target_type', 'attribute');
            $this->set('columnOrders', $killChainOrders);
            $this->set('tabs', $tabs);
            $this->set('scores', $scores);
            $this->set('maxScore', $maxScore);
            if (!empty($colours)) {
                $this->set('colours', $colours['mapping']);
                $this->set('interpolation', $colours['interpolation']);
            }
            $this->set('pickingMode', false);
            if ($matrixData['galaxy']['id'] == $mitre_galaxy_id) {
                $this->set('defaultTabName', "mitre-attack");
                $this->set('removeTrailling', 2);
            }

            $this->set('galaxyName', $matrixData['galaxy']['name']);
            $this->set('galaxyId', $matrixData['galaxy']['id']);
            $matrixGalaxies = $this->Galaxy->getAllowedMatrixGalaxies();
            $this->set('matrixGalaxies', $matrixGalaxies);
        }
        $this->render('statistics_galaxymatrix');
    }

    public function verifyGPG($full = false)
    {
        $user_results = $this->User->verifyGPG($full);
        $this->set('users', $user_results);
    }

    public function verifyCertificate()
    {
        $user_results = $this->User->verifyCertificate();
        $this->set('users', $user_results);
    }

    public function searchGpgKey($email = false)
    {
        $this->_closeSession();
        if (!$this->__canFetchPgpKey()) {
            throw new ForbiddenException(__('Key fetching is disabled.'));
        }
        if (!$email) {
            throw new NotFoundException('No email provided.');
        }
        $keys = $this->User->searchGpgKey($email);
        if (empty($keys)) {
            throw new NotFoundException('No keys found for given email at keyserver.');
        }
        $this->set('keys', $keys);
        $this->layout = false;
        $this->render('ajax/fetchpgpkey');
    }

    public function fetchGpgKey($fingerprint = null)
    {
        if (!$this->__canFetchPgpKey()) {
            throw new ForbiddenException(__('Key fetching is disabled.'));
        }
        if (!$fingerprint) {
            throw new NotFoundException('No fingerprint provided.');
        }
        $key = $this->User->fetchGpgKey($fingerprint);
        if (!$key) {
            throw new NotFoundException('No key with given fingerprint found.');
        }
        return new CakeResponse(['body' => $key]);
    }

    public function getGpgPublicKey()
    {
        if (!Configure::read("MISP.download_gpg_from_homedir")) {
            throw new MethodNotAllowedException("Downloading GPG public key from homedir is not allowed.");
        }

        $key = $this->User->getGpgPublicKey();
        if (!$key) {
            throw new NotFoundException("Public key not found.");
        }

        list($fingeprint, $publicKey) = $key;
        $response = new CakeResponse(array(
            'body' => $publicKey,
            'type' => 'text/plain',
        ));
        $response->download($fingeprint . '.asc');
        return $response;
    }

    public function checkIfLoggedIn()
    {
        return new CakeResponse(array('body'=> 'OK','status' => 200));
    }

    public function admin_monitor($id)
    {
        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => array('User.id' => $id),
            'fields' => array('User.id')
        ));
        if (empty($user)) {
            throw new NotFoundException(__('Invalid user.'));
        }
        $redis = RedisTool::init();
        $alreadyMonitored = $redis->sismember('misp:monitored_users', $id);
        if ($this->request->is('post')) {
            if (isset($this->request->data['User'])) {
                $this->request->data = $this->request->data['User'];
            }
            if (isset($this->request->data['value'])) {
                $this->request->data = $this->request->data['value'];
            }
            if (empty($this->request->data)) {
                $redis->srem('misp:monitored_users', $id);
            } else {
                $redis->sadd('misp:monitored_users', $id);
            }
            return $this->RestResponse->viewData($alreadyMonitored ? 0 : 1, $this->response->type());
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->viewData($alreadyMonitored ? 0 : 1, $this->response->type());
            } else {
                $this->set('data', $alreadyMonitored);
                $this->layout = false;
                $this->render('/Elements/genericElements/toggleForm');
            }
        }
    }

    public function register()
    {
        $fieldToValidate = array('email', 'gpgkey');
        if (empty(Configure::read('Security.allow_self_registration'))) {
            throw new MethodNotAllowedException(__('Self registration is not enabled on this instance.'));
        }
        $message = Configure::read('Security.self_registration_message');
        if (empty($message)) {
            $this->loadModel('Server');
            $message = $this->Server->serverSettings['Security']['self_registration_message']['value'];
        }
        $this->set('message', $message);
        if ($this->request->is('post')) {
            if (isset($this->request->data['User'])) {
                $this->request->data = $this->request->data['User'];
            }
            $validKeys = array(
                'email',
                'org_name',
                'org_uuid',
                'message',
                'pgp',
                'custom_perms',
                'perm_sync',
                'perm_publish',
                'perm_admin'
            );
            $requestObject = array();
            foreach ($validKeys as $key) {
                if (isset($this->request->data[$key])) {
                    $requestObject[$key] = trim($this->request->data[$key]);
                }
            }
            if (!isset($requestObject['message'])) {
                $requestObject['message'] = '';
            }
            if (empty($requestObject['email'])) {
                throw new BadRequestException(__('We require at least the email field to be filled.'));
            }
            $this->User->set($requestObject);
            unset($this->User->validate['email']['unique']);
            if (!$this->User->validates(array('fieldList' => $fieldToValidate))) {
                $errors = $this->User->validationErrors;
                $message = __('Request could not be created.');
                if ($this->_isRest()) {
                    $message .= __('Errors: %s', json_encode($errors));
                    return $this->RestResponse->saveFailResponse('Users', 'register', false, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    return;
                }
            }
            $this->loadModel('Inbox');
            $this->Inbox->create();
            $data = array(
                'Inbox' => array(
                    'title' => __('User registration for %s.', $requestObject['email']),
                    'type' => 'registration',
                    'comment' => $requestObject['message'],
                    'data' => json_encode($requestObject)
                )
            );
            $result = $this->Inbox->save($data);
            if (empty($result)) {
                $message = __('Request could not be created. Make sure that the email and org name fields are filled.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Users', 'register', false, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                }
            } else {
                $message = __('Request sent. The administrators of this community have been notified.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('User', 'register', false, $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect('/');
                }
            }
        }
    }

    public function registrations()
    {
        $this->loadModel('Inbox');
        $params = array(
            'recursive' => -1,
            'conditions' => array(
                'deleted' => 0,
                'type' => 'registration'
            ),
            'order' => array(
                'timestamp desc'
            )
        );
        $passedArgs = $this->passedArgs;
        if (!empty($passedArgs['value'])) {
            $lookup = strtolower($passedArgs['value']);
            $allSearchFields = array('data', 'user_agent', 'ip');
            foreach ($allSearchFields as $field) {
                $params['conditions']['AND']['OR'][] = array('LOWER(Inbox.' . $field . ') LIKE' => '%' . $lookup . '%');
            }
        }
        $this->set('passedArgs', json_encode($passedArgs));
        if ($this->_isRest()) {
            $data = $this->Inbox->find('all', array(
                'recursive' => -1,
                'conditions' => $params['conditions']
            ));
            foreach ($data as $k => $v) {
                $data[$k]['Inbox']['data'] = json_decode($data[$k]['Inbox']['data'], true);
            }
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->paginate = $params;
            $data = $this->paginate('Inbox');
            foreach ($data as $k => $message) {
                $data[$k]['Inbox']['data'] = json_decode($data[$k]['Inbox']['data'], true);
                $data[$k]['Inbox']['requested_role'] = __('default');
                if (!empty($data[$k]['Inbox']['data']['custom_perms'])) {
                    $data[$k]['Inbox']['requested_role'] = array(
                        'perm_publish' => !empty($data[$k]['Inbox']['data']['perm_publish']) ? __('Yes') : __('No'),
                        'perm_sync' => !empty($data[$k]['Inbox']['data']['perm_sync']) ? __('Yes') : __('No'),
                        'perm_admin' => !empty($data[$k]['Inbox']['data']['perm_admin']) ? __('Yes') : __('No')
                    );
                }
            }
            $this->set('data', $data);
        }
    }

    public function discardRegistrations($id = false)
    {
        if (!$this->request->is('post') && !$this->request->is('delete')) {
            $this->set('id', $id);
            $this->set('type', 'discardRegistrations');
            $this->render('ajax/discardRegistrations');
        } else {
            if (empty($id) && !empty($this->params['named']['id'])) {
                $id = $this->params['named']['id'];
            }
            $this->loadModel('Inbox');
            if (!is_array($id)) {
                $id = array($id);
            }
            foreach ($id as $k => $v) {
                if (Validation::uuid($v)) {
                    $id[$k] = $this->Toolbox->findIdByUuid($this->Inbox, $v);
                }
            }
            $registrations = $this->Inbox->find('all', array(
                'recursive' => -1,
                'conditions' => array(
                    'deleted' => 0,
                    'type' => 'registration',
                    'id' => $id
                )
            ));
            foreach ($registrations as $registration) {
                $this->Inbox->delete($registration['Inbox']['id']);
            }
            $message = sprintf(
                '%s registration(s) discarded.',
                count($registrations)
            );
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('User', 'discardRegistrations', false, $this->response->type(), $message);
            } else {
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $this->Log->saveOrFailSilently(array(
                    'org' => $this->Auth->user('Organisation')['name'],
                    'model' => 'User',
                    'model_id' => 0,
                    'email' => $this->Auth->user('email'),
                    'action' => 'discardRegistrations',
                    'title' => $message,
                    'change' => ''
                ));
                $this->Flash->success($message);
                $this->redirect(array('controller' => 'users', 'action' => 'registrations'));
            }
        }
    }

    public function acceptRegistrations($id = false)
    {
        if (empty($id) && !empty($this->params['named']['id'])) {
            $id = $this->params['named']['id'];
        }
        $this->loadModel('Inbox');
        if (Validation::uuid($id)) {
            $id = $this->Toolbox->findIdByUuid($this->Inbox, $id);
        }
        $registrations = $this->Inbox->find('all', array(
            'recursive' => -1,
            'conditions' => array(
                'deleted' => 0,
                'type' => 'registration',
                'id' => $id
            )
        ));
        $suggestedOrg = null;
        $suggestedRole = null;
        $orgCache = array();
        foreach ($registrations as $k => $v) {
            $registrations[$k]['Inbox']['data'] = json_decode($registrations[$k]['Inbox']['data'], true);
            $roleRequirements = array();
            if ($this->request->is('get')) {
                $suggestedOrg = $this->User->Organisation->checkDesiredOrg($suggestedOrg, $registrations[$k]);
                $suggestedRole = $this->User->Role->checkDesiredRole($suggestedRole, $registrations[$k]);
            }
        }
        $default_role = $this->User->Role->find('first', array(
            'recursive' => -1,
            'conditions' => array('Role.default_role' => 1),
            'fields' => array('Role.id')
        ));
        if ($this->request->is('get')) {
            if (!is_array($id)) {
                $id = array($id);
            }
            foreach ($id as $k => $v) {
                $id[$k] = 'id[]:' . intval($v);
            }
            $roles_raw = $this->User->Role->find('all', array(
                'recursive' => -1
            ));
            //roles = id => name
            $roles = array();
            $role_perms = array();
            foreach ($roles_raw as $role) {
                $roles[$role['Role']['id']] = $role['Role']['name'];
                $role_perms[$role['Role']['id']] = array(
                    'perm_publish' => $role['Role']['perm_publish'],
                    'perm_sync' => $role['Role']['perm_sync'],
                    'perm_admin' => $role['Role']['perm_admin']
                );
            }
            if (empty($this->request->data['User'])) {
                $this->request->data = array('User' => $this->request->data);
            }
            if (!empty($default_role)) {
                $this->request->data['User']['role_id'] = $default_role['Role']['id'];
            }
            $this->set('roles', $roles);
            $this->set('role_perms', $role_perms);
            $orgConditions = array('OR' => array('local' => 1));
            if (!empty($suggestedOrg)) {
                $orgConditions['OR'][] = array('Organisation.id' => $suggestedOrg[0]);
            }
            $this->set('orgs', $this->User->Organisation->find('list', array(
                'fields' => array('id', 'name'),
                'recursive' => -1,
                'conditions' => $orgConditions
            )));
            $this->set('registration', $registrations[$k]);
            $this->set('suggestedOrg', $suggestedOrg);
            $this->set('suggestedRole', $suggestedRole);
            $id = implode('/', $id);
            $this->set('id', $id);
            $this->layout = false;
        } else {
            $results = array('successes' => 0, 'fails' => 0);
            if (!isset($this->request->data['User']['role_id'])) {
                if (!empty($default_role)) {
                    $this->request->data['User']['role_id'] = $default_role['Role']['id'];
                } else {
                    throw new BadRequestException(__('Role ID not provided and no default role exist on the instance'));
                }
            }
            if (!isset($this->request->data['User']['org_id'])) {
                throw new BadRequestException(__('No organisation selected. Supply an Organisation ID'));
            } else {
                if (Validation::uuid($this->request->data['User']['org_id'])) {
                    $id = $this->Toolbox->findIdByUuid($this->User->Organisation, $this->request->data['User']['org_id']);
                    $this->request->data['User']['org_id'] = $id;
                }
            }
            foreach ($registrations as $registration) {
                $result = $this->User->registerUser(
                    $this->Auth->user(),
                    $registration['Inbox'],
                    $this->request->data['User']['org_id'],
                    $this->request->data['User']['role_id']
                );
                $results[($result ? 'successes' : 'fails')] += 1;
            }
            $message = array();
            if (!empty($results['successes'])) {
                $message[] = __('Added %s user(s).', $results['successes']);
            }
            if (!empty($results['fails'])) {
                $message[] = __('Could not add %s user(s), reasons for the failure have been logged.', $results['fails']);
            }
            if (empty($message)) {
                $message[] = __('No new users added - there was nothing to add.');
            }
            $message = implode(' ', $message);
            if ($this->_isRest()) {
                if (empty($results['fails']) && !empty($results['successes'])) {
                    return $this->RestResponse->saveSuccessResponse('User', 'acceptRegistrations', false, $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('Users', 'acceptRegistrations', false, $message, $this->response->type());
                }
            } else {
                if (empty($results['fails']) && !empty($results['successes'])) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message)), 'status'=>200, 'type' => 'json'));
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $message)), 'status'=>200, 'type' => 'json'));
                }
            }
        }
    }

    public function updateToAdvancedAuthKeys()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint can only be triggered via POST requests.'));
        }
        $updated = $this->User->updateToAdvancedAuthKeys();
        $message = __('The upgrade process is complete, %s authkey(s) generated.', $updated);
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('User', 'acceptRegistrations', false, $this->response->type(), $message);
        } else {
            $this->Flash->success($message);
            $this->redirect($this->referer());
        }
    }

    public function notificationSettings()
    {
        $user = $this->Auth->user();

        if ($this->request->is('post') || $this->request->is('put')) {
            $success = $this->User->saveNotificationSettings($user['id'], $this->request->data);
            if ($success) {
                $this->_refreshAuth();
                $message = __('Notification settings saved');
                $this->Flash->success($message);
                $this->redirect(['action' => 'view', 'me']);
            } else {
                $message = __('Notification settings could not be saved');
                $this->Flash->error($message);
            }
        }

        $this->request->data = [
            'User' => $user,
            'periodic_settings' => $this->User->fetchPeriodicSettingForUser($user['id']),
        ];
        $this->loadModel('MispAttribute');
        $distributionData = $this->MispAttribute->fetchDistributionData($user);
        unset($distributionData['levels'][5]);
        $this->set('sharingGroups', $distributionData['sgs']);
        $this->set('distributionLevels', $distributionData['levels']);

        $conditions = $this->User->Organisation->createConditions($user);
        $conditions['local'] = true;
        $orgs = $this->User->Organisation->find('list', [
            'conditions' => $conditions,
            'fields' => ['id', 'name'],
            'order' => 'name',
        ]);
        $this->set('orgs', $orgs);
        $this->set('user', $user);
        $this->set('title_for_layout', __('Notification settings'));
    }

    public function viewPeriodicSummary(string $period)
    {
        $userId = $this->Auth->user('id');
        $lastdays = $this->request->params['named']['lastdays'] ?? false;
        $summary = $this->User->generatePeriodicSummary($userId, $period, true, $lastdays);
        $periodicSettings = $this->User->fetchPeriodicSettingForUser($userId);
        $this->set('periodic_settings', $periodicSettings);
        $this->set('summary', $summary);
        $this->set('period', $period);
        $this->set('title_for_layout', __('Periodic summary'));
    }

    private function __canChangePassword()
    {
        return $this->ACL->canUserAccess($this->Auth->user(), 'users', 'change_pw');
    }

    private function __canChangeLogin()
    {
        if ($this->_isSiteAdmin()) {
            return true;
        }
        return !Configure::read('MISP.disable_user_login_change');
    }

    /**
     * Replaces $misp, $org and $contact variables in emails
     * @param string $body
     * @return string
     */
    private function __replaceEmailVariables($body)
    {
        $body = str_replace('$misp', Configure::read('MISP.baseurl'), $body);
        $body = str_replace('$org', Configure::read('MISP.org'), $body);
        $body = str_replace('$contact', Configure::read('MISP.contact'), $body);
        return $body;
    }

    /**
     * @return bool
     */
    private function __canFetchPgpKey()
    {
        return !Configure::read('GnuPG.key_fetching_disabled');
    }

    /**
     * @param int|array $id
     * @return array
     * @throws NotFoundException
     */
    private function __adminFetchConditions($id, $edit = true)
    {
        if (empty($id)) {
            throw new NotFoundException(__('Invalid user'));
        }

        $conditions = ['User.id' => $id];
        $user = $this->Auth->user();
        if (!$user['Role']['perm_site_admin']) {
            $conditions['User.org_id'] = $user['org_id']; // org admin
            if ($edit) {
                $conditions['Role.perm_site_admin'] = false;
            }
        }
        return $conditions;
    }

    public function admin_destroy($id = null)
    {
        $conditionFields = ['id', 'email'];
        $params = $this->IndexFilter->harvestParameters(['id', 'email']);
        if (!empty($id)) {
            $params['id'] = $id;
        }
        $conditions = [];
        foreach ($conditionFields as $conditionField) {
            if (!empty($params[$conditionField])) {
                $conditions[$conditionField . ' LIKE'] = $params[$conditionField];
            }
        }
        if (!empty($conditions)) {
            $userIds = $this->User->find('list', [
                'recursive' => -1,
                'fields' => ['email', 'id'],
                'conditions' => $conditions
            ]);
        } else {
            $userIds = [__('Every user') => 'all'];
        }
        if ($this->request->is('post')) {
            $redis = RedisTool::init();
            $killBefore = time();
            foreach ($userIds as $userId) {
                $redis->set('misp:session_destroy:' . $userId, $killBefore);
            }
            $message = __(
                'Session destruction cutoff set to the current timestamp for the given selection (%s). Session(s) will be destroyed on the next user interaction.',
                implode(', ', array_keys($userIds))
            );
            if ($this->_isRest()) {
                return $this->RestResponse->successResponse(null, $message);
            }
            $this->Flash->success($message);
            $this->redirect($this->referer());
        }

        $this->set(
            'question',
            __(
                'Do you really wish to destroy the session for: %s? The session destruction will occur when the users try to interact with MISP the next time.',
                implode(', ', array_keys($userIds))
            )
        );
        $this->set('title', __('Destroy sessions'));
        $this->set('actionName', 'Destroy');
        $this->render('/genericTemplates/confirm');
    }

    public function view_login_history($userId = null)
    {
        if ($userId && $this->_isAdmin()) {   // org and site admins
            $userExists = (bool) $this->User->find('first', [
                'fields' => ['User' . '.' . 'id'],
                'conditions' => $this->__adminFetchConditions($userId),
                'recursive' => -1,
                'contain' => ['Role'],
            ]);
            if (!$userExists) {
                throw new NotFoundException(__('Invalid user'));
            }
        } else {
            $userId = $this->Auth->user('id');
        }

        $this->loadModel('Log');
        $logs = $this->Log->find('all', array(
            'conditions' => array(
                'Log.user_id' => $userId,
                'OR' => array('Log.action' => array('login', 'login_fail', 'auth', 'auth_fail'))
            ),
            'fields' => array('Log.action', 'Log.created', 'Log.ip', 'Log.change', 'Log.id'),
            'order' => array('Log.id DESC'),
            'limit' => 100          // relatively high limit, as we'll be grouping data afterwards.
        ));

        $profiles = [];
        $prevProfile = null;
        $prevCreatedLast = null;
        $prevCreatedFirst = null;
        $prevLogEntry = null;
        $prevActions = array();

        $actionsTranslator = [
            'auth_fail' => 'API:failed',
            'auth' => 'API:login',
            'login' => 'web:login',
            'login_fail' => 'web:failed'
        ];

        $maxRows = 6;  // limit to a few rows, to prevent cluttering the interface.
                        // We didn't filter the data at SQL query too much, nor by age, as we want to show "enough" data, even if old
        $rows = 0;
        // group authentications by type of loginprofile, to make the list shorter
        foreach ($logs as $logEntry) {
            $loginProfile = $this->User->UserLoginProfile->_fromLog($logEntry['Log']);
            if (!$loginProfile) {
                continue; // skip if empty log
            }
            $loginProfile['ip'] = $logEntry['Log']['ip'] ?? null; // transitional workaround
            if ($this->User->UserLoginProfile->_isSimilar($loginProfile, $prevProfile)) {
                // continue find as same type of login
                $prevCreatedFirst = $logEntry['Log']['created'];
                $prevActions[] = $actionsTranslator[$logEntry['Log']['action']];
            } else {
                // add as new entry
                if (null !== $prevProfile) {
                    $actionsString = '';  // count actions
                    foreach (array_count_values($prevActions) as $action => $cnt) {
                        $actionsString .=  $action . ' (' . $cnt . "x) ";
                    }
                    $profiles[] = [
                        'status' => $this->User->UserLoginProfile->_getTrustStatus($prevProfile, $userId),
                        'platform' => $prevProfile['ua_platform'],
                        'browser' => $prevProfile['ua_browser'],
                        'region' => $prevProfile['geoip'],
                        'ip' =>  $prevProfile['ip'],
                        'accept_lang' => $prevProfile['accept_lang'],
                        'last_seen' => $prevCreatedLast,
                        'first_seen' => $prevCreatedFirst,
                        'actions' => $actionsString,
                        'actions_button' => ('unknown' == $this->User->UserLoginProfile->_getTrustStatus($prevProfile, $userId)) ? true : false,
                        'id' => $prevLogEntry
                    ];
                }
                // build new entry
                $prevProfile = $loginProfile;
                $prevCreatedFirst = $prevCreatedLast = $logEntry['Log']['created'];
                $prevActions[] = $actionsTranslator[$logEntry['Log']['action']];
                $prevLogEntry = $logEntry['Log']['id'];
                $rows++;
                if ($rows === $maxRows) {
                    break;
                }
            }
        }
        // add last entry
        if (null !== $prevProfile) {
            $actionsString = '';  // count actions
            foreach (array_count_values($prevActions) as $action => $cnt) {
                $actionsString .= $action . ' (' . $cnt . "x) ";
            }
            $profiles[] = array(
                'status' => $this->User->UserLoginProfile->_getTrustStatus($prevProfile, $userId),
                'platform' => $prevProfile['ua_platform'],
                'browser' => $prevProfile['ua_browser'],
                'region' => $prevProfile['geoip'],
                'ip' => $prevProfile['ip'],
                'accept_lang' => $prevProfile['accept_lang'],
                'last_seen' => $prevCreatedLast,
                'first_seen' => $prevCreatedFirst,
                'actions' => $actionsString,
                'actions_button' => ('unknown' == $this->User->UserLoginProfile->_getTrustStatus($prevProfile, $userId)) ? true : false,
                'id' => $prevLogEntry
            );
        }
        $this->set('data', $profiles);
        $this->set('user_id', $userId);
    }

    public function logout401()
    {
        # You should read the documentation in docs/CONFIG.ApacheSecureAuth.md
        # before using this endpoint. It is not useful without webserver config
        # changes.
        # To use this, set Plugin.CustomAuth_custom_logout to /users/logout401
        $this->response->statusCode(401);
    }

    public function forgot()
    {
        if (!empty($this->Auth->user()) && !$this->_isRest()) {
            $this->Flash->info(__('You are already logged in, no need to ask for a password reset. Log out first.'));
            $this->redirect('/');
        }
        if ($this->request->is('post')) {
            if (empty($this->request->data['User'])) {
                $this->request->data = ['User' => $this->request->data];
            }
            if (empty($this->request->data['User']['email'])) {
                throw new MethodNotAllowedException(__('No email provided, cannot generate password reset message.'));
            }
            $this->loadModel('Log');
            $this->Log->createLogEntry('SYSTEM', 'forgot', 'User', 0, 'Password reset requested for: ' . $this->request->data['User']['email']);
            $this->User->forgotRouter($this->request->data['User']['email'], $this->User->_remoteIp());
            $message = __('Password reset request submitted. If a valid user is found, you should receive an e-mail with a temporary reset link momentarily. Please be advised that this link is only valid for 10 minutes.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('User', 'forgot', false, $this->response->type(), $message);
            }
            $this->Flash->info($message);
            $this->redirect('/');
        }
    }

    public function password_reset($token)
    {
        $this->loadModel('Server');
        $this->set('complexity', !empty(Configure::read('Security.password_policy_complexity')) ? Configure::read('Security.password_policy_complexity') : $this->Server->serverSettings['Security']['password_policy_complexity']['value']);
        $this->set('length', !empty(Configure::read('Security.password_policy_length')) ? Configure::read('Security.password_policy_length') : $this->Server->serverSettings['Security']['password_policy_length']['value']);
        if (!empty($this->Auth->user()) && !$this->_isRest()) {
            $this->redirect('/');
        }
        $user = $this->User->fetchForgottenPasswordUser($token);
        if (empty($user)) {
            $message = __('Invalid token, or password request token already expired.');
            if ($this->_isRest()) {
                throw new MethodNotAllowedException($message);
            } else {
                $this->Flash->error($message);
                $this->redirect('/');
            }
        }
        if ($this->request->is(['post', 'put'])) {
            $abortPost = false;
            return $this->__pw_change(['User' => $user], 'password_reset', $abortPost, $token, true);
        }
    }

    public function heartbeat()
    {
        $payload = $this->User::HEARTBEAT_MESSAGES[rand(0, count($this->User::HEARTBEAT_MESSAGES)-1)];
        return $this->RestResponse->viewData($payload, 'json');
    }
}
