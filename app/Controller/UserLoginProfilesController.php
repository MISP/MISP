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
            'order' => ['created_at DESC'], // FIXME chri - not working, ask Andras
            'fields' => 'UserLoginProfile.*' // FIXME chri - not working, ask Andras
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

    public function admindelete($id) // FIXME chri - should be admin_delete however gives issues   (note: change also view and ACL)
    {
        if ($this->request->is('post') || $this->request->is('delete')) {
            $profile = $this->UserLoginProfile->find('first', array(
                'conditions' => $this->__deleteFetchConditions($id), // only allow (org/site) admins or own user to delete their data 
                'fields' => ['UserLoginProfile.*']
            ));
            if (empty($profile)) {
                throw new NotFoundException(__('Invalid UserLoginProfile'));
            }
            if ($this->UserLoginProfile->delete($id)) {
                $this->loadModel('Log');
                $fieldsDescrStr = 'UserLoginProfile (' . $id . '): deleted';
                $this->Log->createLogEntry($this->Auth->user(), 'delete', 'UserLoginProfile', $id, $fieldsDescrStr, json_encode($profile));
                
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('UserLoginProfile', 'admin_delete', $id, $this->response->type(), 'UserLoginProfile deleted.');
                } else {
                    $this->Flash->success(__('UserLoginProfile deleted'));
                    $this->redirect(array('action' => 'index', $profile['UserLoginProfile']['user_id']));
                }
            }
            $this->Flash->error(__('UserLoginProfile was not deleted'));
            $this->redirect(array('action' => 'index', $profile['UserLoginProfile']['user_id']));
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
            $this->__setTrust($logId, 'malicious');
            $this->Flash->info(__('You marked a login suspicious. We highly recommend you to change your password NOW !'));
            $this->loadModel('Log');
            $details = 'User reported suspicious login for log ID: '. $logId;
            // raise an alert (the SIEM component should ensure (org)admins are informed)
            $this->Log->createLogEntry($this->Auth->user(), 'auth_alert', 'User', $this->Auth->user('id'), 'Suspicious login reported.', $details);
            // FIXME chri - also inform (org) admins.
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
        // LATER check if the userLoginProfile is already there, or not
        // add it if it isn't there yet
        $data = $this->UserLoginProfile->_fromLog($log['Log']);
        $data['status'] = $status;
        $data['user_id'] = $user['id'];
        $this->UserLoginProfile->save($data);
    }

}
