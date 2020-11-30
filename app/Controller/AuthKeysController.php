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
            'AuthKey.name' => 'ASC',
        )
    );

    public function index($id = false)
    {
        $conditions = $this->__prepareConditions();
        if ($id !== false) {
            $this->set('user_id', $id);
            $conditions['AND'][] = ['AuthKey.user_id' => $id];
        }
        $this->CRUD->index([
            'filters' => ['User.username', 'authkey', 'comment', 'User.id'],
            'quickFilters' => ['authkey', 'comment'],
            'contain' => ['User'],
            'conditions' => $conditions,
            'afterFind' => function (array $authKeys) {
                foreach ($authKeys as &$authKey) {
                    unset($authKey['AuthKey']['authkey']);
                }
                return $authKeys;
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('metaGroup', $this->_isAdmin ? 'admin' : 'globalActions');
        $this->set('metaAction', 'authkeys_index');
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
        $this->CRUD->view($id, [
            'contain' => ['User.id', 'User.email'],
            'conditions' => $this->__prepareConditions(),
            'afterFind' => function (array $authKey) {
                unset($authKey['AuthKey']['authkey']);
                return $authKey;
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', [
            'menuList' => $this->_isSiteAdmin() ? 'admin' : 'globalActions',
            'menuItem' => 'authKeyView',
        ]);
    }

    /**
     * Return conditions according to current user permission.
     * @return array
     */
    private function __prepareConditions()
    {
        $user = $this->Auth->user();
        if ($user['Role']['perm_site_admin']) {
            $conditions = []; // site admin can see all keys
        } else if ($user['Role']['perm_admin']) {
            $conditions['AND'][]['User.org_id'] = $user['org_id']; // org admin can see his/her user org auth keys
        } else {
            $conditions['AND'][]['User.id'] = $user['id'];
        }
        return $conditions;
    }
}
