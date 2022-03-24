<?php
App::uses('AppController', 'Controller');

/**
 * @property AuthKey $AuthKey
 */
class AuthKeysController extends AppController
{
    public $components = array(
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
        $canCreateAuthkey = true;
        if ($id) {
            $this->set('user_id', $id);
            if ($this->_isAdmin()) {
                if ($this->_isSiteAdmin()) {
                    $canCreateAuthkey = true;
                } else {
                    $user = $this->AuthKey->User->find('first', [
                        'recursive' => -1,
                        'conditions' => [
                            'User.id' => $id,
                            'User.disabled' => false
                        ],
                        'fields' => ['User.id', 'User.org_id', 'User.disabled'],
                        'contain' => [
                            'Role' => [
                                'fields' => [
                                    'Role.perm_site_admin', 'Role.perm_admin'
                                ]
                            ]
                        ]
                    ]);
                    if ($user['Role']['perm_site_admin'] || ($user['Role']['perm_admin'] && $user['User']['id'] !== $this->Auth->user('id'))) {
                        $canCreateAuthkey = false;
                    } else {
                        $canCreateAuthkey = true;
                    }
                }
            } else {
                $canCreateAuthkey = (int)$id === (int)$this->Auth->user('id');
            }
            $conditions['AND'][] = ['AuthKey.user_id' => $id];
        }
        $this->set('canCreateAuthkey', $canCreateAuthkey);
        $keyUsageEnabled = Configure::read('MISP.log_user_ips') && Configure::read('MISP.log_user_ips_authkeys');
        $this->CRUD->index([
            'filters' => ['User.email', 'authkey_start', 'authkey_end', 'comment', 'User.id'],
            'quickFilters' => ['comment', 'authkey_start', 'authkey_end', 'User.email'],
            'contain' => ['User.id', 'User.email'],
            'conditions' => $conditions,
            'afterFind' => function (array $authKeys) use ($keyUsageEnabled) {
                if ($keyUsageEnabled) {
                    $keyIds = Hash::extract($authKeys, "{n}.AuthKey.id");
                    $lastUsedById = $this->AuthKey->getLastUsageForKeys($keyIds);
                }
                foreach ($authKeys as &$authKey) {
                    if ($keyUsageEnabled) {
                        $lastUsed = $lastUsedById[$authKey['AuthKey']['id']];
                        $authKey['AuthKey']['last_used'] = $lastUsed;
                    }
                    unset($authKey['AuthKey']['authkey']);
                }
                return $authKeys;
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('title_for_layout', __('Auth Keys'));
        $this->set('advancedEnabled', !empty(Configure::read('Security.advanced_authkeys')));
        $this->set('keyUsageEnabled', $keyUsageEnabled);
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

    public function edit($id)
    {
        $this->CRUD->edit($id, [
            'conditions' => $this->__prepareConditions(),
            'afterFind' => function (array $authKey) {
                unset($authKey['AuthKey']['authkey']);
                if (is_array($authKey['AuthKey']['allowed_ips'])) {
                    $authKey['AuthKey']['allowed_ips'] = implode("\n", $authKey['AuthKey']['allowed_ips']);
                }
                $authKey['AuthKey']['expiration'] = date('Y-m-d H:i:s', $authKey['AuthKey']['expiration']);
                return $authKey;
            },
            'fields' => ['comment', 'allowed_ips', 'expiration', 'read_only'],
            'contain' => ['User.id', 'User.org_id']
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('dropdownData', [
            'user' => $this->User->find('list', [
                'sort' => ['username' => 'asc'],
                'conditions' => ['id' => $this->request->data['AuthKey']['user_id']],
            ])
        ]);
        $this->set('menuData', [
            'menuList' => $this->_isSiteAdmin() ? 'admin' : 'globalActions',
            'menuItem' => 'authKeyAdd',
        ]);
        $this->set('edit', true);
        $this->set('validity', Configure::read('Security.advanced_authkeys_validity'));
        $this->set('title_for_layout', __('Edit auth key'));
        $this->render('add');
    }

    public function add($user_id = false)
    {
        $options = $this->IndexFilter->harvestParameters(['user_id']);
        if (!empty($params['user_id'])) {
            $user_id = $options['user_id'];
        }
        $params = [
            'displayOnSuccess' => 'authkey_display',
            'saveModelVariable' => ['authkey_raw'],
            'override' => ['authkey' => null], // do not allow to use own key, always generate random one
            'afterFind' => function ($authKey) { // remove hashed key from response
                unset($authKey['AuthKey']['authkey']);
                return $authKey;
            }
        ];
        if ($user_id === 'me' || $user_id === false) {
            $user_id = $this->Auth->user('id');
        }
        $selectConditions = [];
        if (!$this->_isSiteAdmin()) {
            if ($this->_isAdmin()) {
                $role_ids = $this->AuthKey->User->Role->find('column', [
                    'fields' => ['Role.id'],
                    'conditions' => [
                        'AND' => [
                            'Role.perm_site_admin' => false,
                            'Role.perm_auth' => true,
                            'Role.perm_admin' => false
                        ]
                    ]
                ]);
                $user_ids = $this->AuthKey->User->find('column', [
                    'fields' => ['User.id'],
                    'conditions' => [
                        'User.org_id' => $this->Auth->user('org_id'),
                        'OR' => [
                            'User.role_id' => $role_ids,
                            'User.id' => $this->Auth->user('id')
                        ]
                    ]
                ]);
                if (!empty($user_id)) {
                    if (in_array($user_id, $user_ids)) {
                        $user_ids = [$user_id];
                    } else {
                        throw new MethodNotAllowedException(__('Invalid user or insufficient privileges to create an authkey for the given user.'));
                    }
                }
                $selectConditions['AND'][] = ['User.id' => $user_ids];
                $params['override']['user_id'] = $user_ids;
            } else {
                $selectConditions['AND'][] = ['User.id' => $this->Auth->user('id')];
                $params['override']['user_id'] = $this->Auth->user('id');
            }
        } else if ($user_id) {
            $selectConditions['AND'][] = ['User.id' => $user_id];
            $params['override']['user_id'] = $user_id;
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
        $this->set('title_for_layout', __('Add auth key'));
        $this->set('menuData', [
            'menuList' => $this->_isSiteAdmin() ? 'admin' : 'globalActions',
            'menuItem' => 'authKeyAdd',
        ]);
        $this->set('validity', Configure::read('Security.advanced_authkeys_validity'));
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

        if (Configure::read('MISP.log_user_ips') && Configure::read('MISP.log_user_ips_authkeys')) {
            list($keyUsage, $lastUsed, $uniqueIps) = $this->AuthKey->getKeyUsage($id);
            $this->set('keyUsage', $keyUsage);
            $this->set('lastUsed', $lastUsed);
            $this->set('uniqueIps', $uniqueIps);
        }

        $this->set('title_for_layout', __('Auth key'));
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
