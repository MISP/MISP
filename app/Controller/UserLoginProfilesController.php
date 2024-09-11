<?php
App::uses('AppController', 'Controller');

/**
 * @property UserLoginProfile $UserLoginProfile
 */
class UserLoginProfilesController extends AppController
{
    public $components = array(
        'CRUD',
        'RequestHandler'
    );

    public $paginate = array(
        'limit' => 60,
        'order' => array(
            'UserLoginProfile.created_at' => 'DESC',
        )
    );

    private $user_allowed_fields = [
        'id',
        'org_id',
        'server_id',
        'email',
        'autoalert',
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
    ];

    public function index($user_id = null)
    {
        $delete_buttons = false;
        // normal user
        $conditions = ['user_id' => $this->Auth->user('id')];
        // org admin can see people from their own org
        if (!$this->_isSiteAdmin() && $this->_isAdmin()) { 
            $conditions = ['User.org_id' => $this->Auth->user('org_id'),
                           'user_id' => $user_id]; 
            $delete_buttons = true;
        }
        // full admin can see all users
        else if ($this->_isSiteAdmin()) {
            $conditions = ['user_id' => $user_id];
            $delete_buttons = true;
        }
        $this->CRUD->index([
            'conditions' => $conditions,
            'afterFind' => function(array $userLoginProfiles) {
                foreach ($userLoginProfiles as $i => $userLoginProfile) {
                    foreach ($userLoginProfile['User'] as $field => $value) {
                        if (!in_array($field, $this->user_allowed_fields)) {
                            unset($userLoginProfiles[$i]['User'][$field]);
                        }
                    }
                }
                return $userLoginProfiles;
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('title_for_layout', __('UserLoginProfiles'));
        $this->set('menuData', [
            'menuList' => $this->_isSiteAdmin() ? 'admin' : 'globalActions',
            'menuItem' => 'authkeys_index',
        ]);
        $this->set('delete_buttons', $delete_buttons);
    }
    
    /**
     * @param int|array $id
     * @return array
     * @throws NotFoundException
     */
    private function __deleteFetchConditions($id)
    {
        if (empty($id)) {
            throw new NotFoundException(__('Invalid userloginprofile'));
        }
        $conditions = ['UserLoginProfile.id' => $id];
        if ($this->_isSiteAdmin()) {
            // no additional filter for siteadmins
        }
        else if ($this->_isAdmin()) {
            $conditions['User.org_id'] = $this->Auth->user('org_id'); // org admin
        } 
        else {
            $conditions['UserLoginProfile.user_id'] = $this->Auth->user('id');  // normal user
        }
        return $conditions;
    }

    public function admin_delete($id)
    {
        if ($this->request->is('post') || $this->request->is('delete')) {
            $profile = $this->UserLoginProfile->find('first', array(
                'conditions' => $this->__deleteFetchConditions($id), // only allow (org/site) admins or own user to delete their data 
                'fields' => ['UserLoginProfile.*']
            ));
            if (empty($profile)) {
                throw new NotFoundException(__('Invalid user login profile'));
            }
            if ($this->UserLoginProfile->delete($id)) {
                $this->loadModel('Log');
                $fieldsDescrStr = 'UserLoginProfile (' . $id . '): deleted';
                $this->Log->createLogEntry($this->Auth->user(), 'delete', 'UserLoginProfile', $id, $fieldsDescrStr, json_encode($profile));
                
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('UserLoginProfile', 'admin_delete', $id, $this->response->type(), 'User login profile deleted.');
                } else {
                    $this->Flash->success(__('UserLoginProfile deleted'));
                    $this->redirect(array('admin'=> false, 'controller' => 'userLoginProfiles', 'action' => 'index', $profile['UserLoginProfile']['user_id']));
                }
            }
            $this->Flash->error(__('User login profile was not deleted'));
            $this->redirect(array('admin'=> false, 'controller' => 'userLoginProfiles', 'action' => 'index', $profile['UserLoginProfile']['user_id']));
        }
    }

    public function trust($logId)
    {
        if ($this->request->is('post')) {
            $this->__setTrust($logId, 'trusted');
        }
        $this->redirect(array('controller' => 'users', 'action' => 'view_login_history'));
    }

    public function malicious($logId)
    {
        if ($this->request->is('post')) {
            $userLoginProfile = $this->__setTrust($logId, 'malicious');
            $this->Flash->info(__('You marked a login suspicious. You must change your password NOW!'));
            $this->loadModel('Log');
            $details = 'User reported suspicious login for log ID: '. $logId;
            // raise an alert (the SIEM component should ensure (org)admins are informed)
            $this->Log->createLogEntry($this->Auth->user(), 'auth_alert', 'User', $this->Auth->user('id'), 'Suspicious login reported.', $details);
            // inform (org)admins of the report, they might want to action this...
            $user = $this->User->find('first', array(
                'conditions' => array(
                    'User.id' => $this->Auth->user('id')
                ),
                'recursive' => -1
            ));
            unset($user['User']['password']);
            $this->UserLoginProfile->emailReportMalicious($user, $userLoginProfile);
            // change account info to force password change, redirect to new password page.
            $this->User->id = $this->Auth->user('id');
            $this->User->saveField('change_pw', 1);
            $this->redirect(array('controller' => 'users', 'action' => 'change_pw'));
            return;
        }
        $this->redirect(array('controller' => 'users', 'action' => 'view_login_history'));        
    }

    private function __setTrust($logId, $status)
    {
        $user = $this->Auth->user();
        $this->loadModel('Log');
        $log = $this->Log->find('first', array(
            'conditions' => array(
                'Log.user_id' => $user['id'],
                'Log.id' => $logId,
                'OR' => array ('Log.action' => array('login', 'login_fail', 'auth', 'auth_fail'))
            ),
            'fields' => array('Log.action', 'Log.created', 'Log.ip', 'Log.change', 'Log.id'),
            'order' => array('Log.created DESC')
        ));
        $data = $this->UserLoginProfile->_fromLog($log['Log']);
        if (!$data) return $data; // skip if empty logs
        $data['status'] = $status;
        $data['user_id'] = $user['id'];
        $data['hash'] = $this->UserLoginProfile->hash($data);

        // add the userLoginProfile trust status if it not already there, based on the hash
        $exists = $this->UserLoginProfile->hasAny([
            'UserLoginProfile.hash' => $data['hash']
        ]);
        if (!$exists) {
            // no row yet, save it. 
            $this->UserLoginProfile->save($data);
        }
        return $data;
    }
}
