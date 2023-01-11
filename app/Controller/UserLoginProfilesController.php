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

    public function index($id = false)
    {
        
        $this->CRUD->index([
            // 'filters' => ['User.email', 'authkey_start', 'authkey_end', 'comment', 'User.id'],
            // 'quickFilters' => ['comment', 'authkey_start', 'authkey_end', 'User.email'],
            // 'contain' => ['User.id', 'User.email'],
            'conditions' => ['user_id' => $this->Auth->user('id')],
            'order' => ['created_at DESC'] // FIXME chri - not working, ask Andras
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('title_for_layout', __('UserLoginProfiles'));
        $this->set('menuData', [
            'menuList' => $this->_isSiteAdmin() ? 'admin' : 'globalActions',
            'menuItem' => 'authkeys_index',
        ]);
    }
    
    public function delete($id)
    {
        $this->CRUD->delete($id, [
            'conditions' => $this->__prepareConditions(),
            'contain' => ['User'],
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function trust($logId)
    {
        if ($this->request->is('post')) {
            $this->__setTrust($logId, 'trusted');
        }
        $this->redirect(array('controller' => 'users', 'action' => 'view_auth_history'));
    }

    public function malicious($logId)
    {
        if ($this->request->is('post')) {
            $this->__setTrust($logId, 'malicious');
        }
        $this->redirect(array('controller' => 'users', 'action' => 'view_auth_history'));
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
        debug($log);
        // check if the userLoginProfile is already there, or not

        // add it if it isn't there yet
        $data = $this->UserLoginProfile->_fromLog($log['Log']);
        $data['status'] = $status;
        $data['user_id'] = $user['id'];
        // debug($data);
        $this->UserLoginProfile->save($data);
        // debug($this->UserLoginProfile);
        debug("Saved");
        if (empty($log)) {
            // FIXME throw error saying there is an issue.
        }

    }

}
