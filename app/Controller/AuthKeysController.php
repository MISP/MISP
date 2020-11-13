<?php

App::uses('AppController', 'Controller');

class AuthKeysController extends AppController
{
    public $components = array(
        'Security',
        'CRUD',
        'RequestHandler'
    );

    public $paginate = array(
            'limit' => 60,
            'order' => array(
                'AuthKey.name' => 'ASC'
            )
    );

    public function index($id = false)
    {
        $conditions = [];
        if (!$this->_isAdmin()) {
            $conditions['AND'][] = ['AuthKey.user_id' => $this->Auth->user('id')];
        } else if (!$this->_isSiteAdmin()) {
            $userIds = $this->AuthKey->User->find('list', [
                'conditions' => ['User.org_id' => $this->Auth->user('org_id')],
                'fields' => ['User.id', 'User.id']
            ]);
            $conditions['AND'][] = ['AuthKey.user_id' => array_values($userIds)];
        }
        if ($id !== false) {
            $this->set('user_id', $id);
            $conditions['AND'][] = ['AuthKey.user_id' => $id];
        }
        $this->CRUD->index([
            'filters' => ['User.username', 'authkey', 'comment', 'User.id'],
            'quickFilters' => ['authkey', 'comment'],
            'contain' => ['User'],
            'exclude_fields' => ['authkey'],
            'conditions' => $conditions
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('metaGroup', $this->_isAdmin ? 'admin' : 'globalActions');
        $this->set('metaAction', 'authkeys_index');
    }

    public function delete($id)
    {
        $params = [];
        if (!$this->_isAdmin()) {
            $params['conditions'] = ['user_id' => $this->Auth->user('id')];
        }
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function edit($id)
    {
        $this->set('metaGroup', 'admin');
        $this->set('metaAction', 'authkeys_edit');
    }

    public function add($user_id = false)
    {
        $this->set('menuData', array('menuList' => $this->_isSiteAdmin() ? 'admin' : 'globalActions', 'menuItem' => 'authKeyAdd'));
        $params = [
            'displayOnSuccess' => 'authkey_display',
            'saveModelVariable' => ['authkey_raw']
        ];
        $selectConditions = [];
        if (!$this->_isSiteAdmin()) {
            $selectConditions['AND'][] = ['User.id' => $this->Auth->user('id')];
            $params['override'] = ['user_id' => $this->Auth->user('id')];
        } else if ($user_id) {
            $selectConditions['AND'][] = ['User.id' => $user_id];
            $params['override'] = ['user_id' => $user_id];
        }
        $this->CRUD->add($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->loadModel('User');
        $dropdownData = [
            'user' => $this->User->find('list', [
                'sort' => ['username' => 'asc'],
                'conditions' => $selectConditions
            ])
        ];
        $this->set(compact('dropdownData'));
    }

    public function view($id = false)
    {
        $this->set('menuData', array('menuList' => $this->_isSiteAdmin() ? 'admin' : 'globalActions', 'menuItem' => 'authKeyView'));
        $this->CRUD->view($id, ['contain' => ['User.id', 'User.email']]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
