<?php

namespace App\Controller;

use App\Controller\AppController;
use Cake\Core\Configure;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Utility\Hash;

class AuthKeysController extends AppController
{
    use LocatorAwareTrait;

    public $paginate = [
        'limit' => 60,
        'maxLimit' => 9999,
        'order' => [
            'Authkey.id' => 'DESC'
        ],
    ];

    public function index($user_id = false)
    {
        $conditions = $this->__prepareConditions();
        $canCreateAuthkey = $this->__canCreateAuthKeyForUser($user_id);
        if ($user_id) {
            $this->set('user_id', $user_id);
            $conditions['AND'][] = ['AuthKeys.user_id' => $user_id];
        }
        $this->set('canCreateAuthkey', $canCreateAuthkey);
        $keyUsageEnabled = Configure::read('MISP.log_user_ips') && Configure::read('MISP.log_user_ips_authkeys');
        $this->CRUD->index(
            [
                'filters' => ['Users.email', 'authkey_start', 'authkey_end', 'comment', 'Users.id'],
                'quickFilters' => ['comment', 'authkey_start', 'authkey_end', 'Users.email'],
                'conditions' => $conditions,
                'contain' => ['Users' => ['fields' => ['id', 'email']]],
                'afterFind' => function ($authKeys) use ($keyUsageEnabled) {
                if ($keyUsageEnabled) {
                    $keyIds = Hash::extract($authKeys, "{n}.AuthKey.id");
                    $lastUsedById = $this->AuthKey->getLastUsageForKeys($keyIds);
                }
                foreach ($authKeys as &$authKey) {
                    if ($keyUsageEnabled) {
                        $lastUsed = $lastUsedById[$authKey['id']];
                        $authKey['last_used'] = $lastUsed;
                    }
                }
                return $authKeys;
            }
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('title_for_layout', __('Auth Keys'));
        $this->set('advancedEnabled', !empty(Configure::read('Security.advanced_authkeys')));
        $this->set('keyUsageEnabled', $keyUsageEnabled);
        $this->set(
            'menuData',
            [
                'menuList' => $this->isSiteAdmin() ? 'admin' : 'globalActions',
                'menuItem' => 'authkeys_index',
            ]
        );
    }

    public function delete($id)
    {
        if (!$this->__canEditAuthKey($id)) {
            throw new MethodNotAllowedException(__('Invalid user or insufficient privileges to interact with an authkey for the given user.'));
        }
        $this->CRUD->delete(
            $id,
            [
                'conditions' => $this->__prepareConditions(),
                'contain' => ['Users'],
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function edit($id)
    {
        if (!$this->__canEditAuthKey($id)) {
            throw new MethodNotAllowedException(__('Invalid user or insufficient privileges to interact with an authkey for the given user.'));
        }
        $this->CRUD->edit(
            $id,
            [
                'conditions' => $this->__prepareConditions(),
                'afterFind' => function (\App\Model\Entity\AuthKey $authKey) {
                return $authKey;
            },
                'fields' => ['comment', 'allowed_ips', 'expiration', 'read_only'],
                'contain' => ['Users' => ['fields' => ['id', 'org_id']]]
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set(
            'dropdownData',
            [
                'user' => $this->Users->find(
                    'list',
                    [
                        'sort' => ['username' => 'asc'],
                        'conditions' => ['id' => $this->entity['user_id']],
                    ]
                )
            ]
        );
        $this->set(
            'menuData',
            [
                'menuList' => $this->isSiteAdmin() ? 'admin' : 'globalActions',
                'menuItem' => 'authKeyAdd',
            ]
        );
        $this->set('edit', true);
        $this->set('validity', Configure::read('Security.advanced_authkeys_validity'));
        $this->set('title_for_layout', __('Edit auth key'));
        $this->render('add');
    }

    public function add($user_id = false)
    {
        $loggedUser = $this->ACL->getUser();
        $options = $this->request->getParam('user_id');
        if (!empty($params['user_id'])) {
            $user_id = $options['user_id'];
        }
        $params = [
            'displayOnSuccess' => 'authkey_display',
            'override' => ['authkey' => null], // do not allow to use own key, always generate random one
            'afterFind' => function (array $authKey, array $savedData) { // remove hashed key from response
                unset($authKey['authkey']);
                $authKey['authkey_raw'] = $savedData['authkey_raw'];
                return $authKey;
            }
        ];
        if ($user_id === 'me' || $user_id === false) {
            $user_id = $loggedUser->id;
        }
        $selectConditions = [];
        if ($user_id) {
            if ($this->__canCreateAuthKeyForUser($user_id)) {
                $selectConditions['AND'][] = ['Users.id' => $user_id];
                $params['override']['user_id'] = $user_id;
            } else {
                throw new MethodNotAllowedException(__('Invalid user or insufficient privileges to interact with an authkey for the given user.'));
            }
        } else {
            $selectConditions['AND'][] = ['Users.id' => $loggedUser->id];
            $params['override']['user_id'] = $loggedUser->id;
        }
        $this->CRUD->add($params);
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }
        $dropdownData = [
            'user' => $this->AuthKeys->Users->find(
                'list',
                [
                    'sort' => ['username' => 'asc'],
                    'conditions' => $selectConditions,
                ]
            )
        ];
        $this->set(compact('dropdownData'));
        $this->set('title_for_layout', __('Add auth key'));
        $this->set(
            'menuData',
            [
                'menuList' => $this->isSiteAdmin() ? 'admin' : 'globalActions',
                'menuItem' => 'authKeyAdd',
            ]
        );
        $this->set('validity', Configure::read('Security.advanced_authkeys_validity'));
    }

    public function view($id = false)
    {
        $this->CRUD->view(
            $id,
            [
                'contain' => ['Users' => ['fields' => ['id', 'email']]],
                'conditions' => $this->__prepareConditions(),
                'afterFind' => function (\App\Model\Entity\AuthKey $authKey) {
                return $authKey;
            }
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }

        if (Configure::read('MISP.log_user_ips') && Configure::read('MISP.log_user_ips_authkeys')) {
            list($keyUsage, $lastUsed, $uniqueIps) = $this->AuthKey->getKeyUsage($id);
            $this->set('keyUsage', $keyUsage);
            $this->set('lastUsed', $lastUsed);
            $this->set('uniqueIps', $uniqueIps);
        }

        $this->set('title_for_layout', __('Auth key'));
        $this->set(
            'menuData',
            [
                'menuList' => $this->isSiteAdmin() ? 'admin' : 'globalActions',
                'menuItem' => 'authKeyView',
            ]
        );
    }

    public function pin($id, $ip)
    {
        if (!$this->__canEditAuthKey($id)) {
            throw new MethodNotAllowedException(__('Invalid user or insufficient privileges to interact with an authkey for the given user.'));
        }
        if ($this->request->is('post')) {
            // find entry, to confirm user is authorized
            $conditions = $this->__prepareConditions();
            $conditions['AND'][]['id'] = $id;
            $authKey = $this->AuthKeys->find(
                'all',
                [
                    'conditions' => $conditions,
                    'recursive' => 1
                ]
            )->first();
            // update the key with the source IP
            if ($authKey) {
                $authKey['allowed_ips'] = $ip;
                $this->AuthKey->save($authKey, ['fieldList' => ['allowed_ips']]);
                $this->Flash->success(__('IP address set as allowed source for the Key.'));
            } else {
                $this->Flash->error(__('Failed to set IP as source'));
            }
        }
        $this->redirect($this->referer());
        // $this->redirect(['controller' => 'auth_keys', 'view' => 'index']);
    }

    /**
     * Return conditions according to current user permission.
     * @return array
     */
    private function __prepareConditions()
    {
        $user = $this->ACL->getUser();
        if ($user['Role']['perm_site_admin']) {
            $conditions = []; // site admin can see/edit all keys
        } else if ($user['Role']['perm_admin']) {
            $conditions['AND'][]['org_id'] = $user['org_id']; // org admin can see his/her user org auth keys
        } else {
            $conditions['AND'][]['id'] = $user['id'];
        }
        return $conditions;
    }

    private function __canCreateAuthKeyForUser($user_id)
    {
        $loggedUser = $this->ACL->getUser();
        if (!$user_id)
            return true;
        if ($this->isAdmin) {
            if ($this->isSiteAdmin()) {
                return true;   // site admin is OK for all
            } else {
                // org admin only for non-admin users and themselves
                $user = $this->AuthKey->User->find(
                    'all',
                    [
                        'recursive' => -1,
                        'conditions' => [
                            'User.id' => $user_id,
                            'User.disabled' => false
                        ],
                        'fields' => ['User.id', 'User.org_id', 'User.disabled'],
                        'contain' => [
                            'Role' => [
                                'fields' => [
                                    'Role.perm_site_admin', 'Role.perm_admin', 'Role.perm_auth'
                                ]
                            ]
                        ]
                    ]
                )->first();
                if (
                    $user['Role']['perm_site_admin'] ||
                    ($user['Role']['perm_admin'] && $user['User']['id'] !== $loggedUser->id) ||
                    !$user['Role']['perm_auth']
                ) {
                    // no create/edit for site_admin or other org admin
                    return false;
                } else {
                    // ok for themselves or users
                    return true;
                }
            }
        } else {
            // user for themselves
            return (int)$user_id === (int)$loggedUser->id;
        }
    }

    private function __canEditAuthKey($key_id)
    {
        $user_id = $this->AuthKeys->find(
            'column',
            [
                'fields' => ['user_id'],
                'conditions' => [
                    'id' => $key_id
                ]
            ]
        );
        return $this->__canCreateAuthKeyForUser($user_id);
    }
}
