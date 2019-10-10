<?php

/*
 *
 * Feature developed as part of a training given by CIRCL in Luxembourg on 26/09/2019
 * Verbose comments for educational purposes only
 *
 */

App::uses('AppController', 'Controller');

class UserSettingsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999,
        'order' => array(
            'UserSetting.id' => 'DESC'
        ),
        'contain' => array(
            'User.id',
            'User.email'
        )
    );

    public function index()
    {
        $filterData = array(
            'request' => $this->request,
            'paramArray' => array('setting', 'user_id', 'sort', 'direction', 'page', 'limit'),
            'named_params' => $this->params['named']
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception);
        $conditions = array();
        if (!empty($filters['setting'])) {
            $conditions['AND'][] = array(
                'setting' => $filters['setting']
            );
        }
        if (!empty($filters['user_id'])) {
            if ($filters['user_id'] === 'all') {
                $context = 'all';
            } else if ($filters['user_id'] === 'me') {
                $conditions['AND'][] = array(
                    'user_id' => $this->Auth->user('id')
                );
                $context = 'me';
            } else if ($filters['user_id'] === 'org') {
                $conditions['AND'][] = array(
                    'user_id' => $this->UserSetting->User->find(
                        'list', array(
                            'conditions' => array(
                                'User.org_id' => $this->Auth->user('org_id')
                            ),
                            'fields' => array(
                                'User.id', 'User.id'
                            )
                        )
                    )
                );
                $context = 'org';
            } else {
                $conditions['AND'][] = array(
                    'user_id' => $filters['user_id']
                );
            }
        }
        if (!$this->_isSiteAdmin()) {
            if ($this->_isAdmin()) {
                $conditions['AND'][] = array(
                    'UserSetting.user_id' => $this->UserSetting->User->find(
                        'list', array(
                            'conditions' => array(
                                'User.org_id' => $this->Auth->user('org_id')
                            ),
                            'fields' => array(
                                'User.id', 'User.id'
                            )
                        )
                    )
                );
            } else {
                $conditions['AND'][] = array(
                    'UserSetting.user_id' => $this->Auth->user('id')
                );
            }
        }
        if ($this->_isRest()) {
            $params = array(
                'conditions' => $conditions
            );
            if (!empty($filters['page'])) {
                $params['page'] = $filters['page'];
                $params['limit'] = $this->paginate['limit'];
            }
            if (!empty($filters['limit'])) {
                $params['limit'] = $filters['limit'];
            }
            $userSettings = $this->UserSetting->find('all', $params);
            return $this->RestResponse->viewData($userSettings, $this->response->type());
        } else {
            $this->paginate['conditions'] = $conditions;
            $data = $this->paginate();
            foreach ($data as $k => $v) {
                if (!empty($this->UserSetting->validSettings[$v['UserSetting']['setting']])) {
                    $data[$k]['UserSetting']['restricted'] = empty($this->UserSetting->validSettings[$v['UserSetting']['setting']]['restricted']) ? '' : $this->UserSetting->validSettings[$v['UserSetting']['setting']]['restricted'];
                } else {
                    $data[$k]['UserSetting']['restricted'] = array();
                }
            }
            $this->set('data', $data);
            $this->set('context', empty($context) ? 'null' : $context);
        }
    }

    public function view($id)
    {
        // check if the ID is valid and whether a user setting with the given ID exists
        if (empty($id) || !is_numeric($id)) {
            throw new InvalidArgumentException(__('Invalid ID passed.'));
        }
        $userSetting = $this->UserSetting->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'UserSetting.id' => $id
            ),
            'contain' => array('User.id', 'User.org_id')
        ));
        if (empty($userSetting)) {
            throw new NotFoundException(__('Invalid user setting.'));
        }
        $checkAccess = $this->UserSetting->checkAccess($this->Auth->user(), $userSetting);
        if (!$checkAccess) {
            throw new NotFoundException(__('Invalid user setting.'));
        }
        if ($this->_isRest()) {
            unset($userSetting['User']);
            return $this->RestResponse->viewData($userSetting, $this->response->type());
        } else {
            $this->set($data, $userSetting);
        }
    }

    public function setSetting($user_id = false, $setting = false)
    {
        if (!empty($setting)) {
            if (!$this->UserSetting->checkSettingValidity($setting)) {
                throw new MethodNotAllowedException(__('Invalid setting.'));
            }
            $settingPermCheck = $this->UserSetting->checkSettingAccess($this->Auth->user(), $setting);
            if ($settingPermCheck !== true) {
                throw new MethodNotAllowedException(__('This setting is restricted and requires the following permission(s): %s', $settingPermCheck));
            }
        }
        // handle POST requests
        if ($this->request->is('post')) {
            // massage the request to allow for unencapsulated POST requests via the API
            // {"key": "value"} instead of {"UserSetting": {"key": "value"}}
            if (empty($this->request->data['UserSetting'])) {
                $this->request->data = array('UserSetting' => $this->request->data);
            }
            if (!empty($user_id)) {
                $this->request->data['UserSetting']['user_id'] = $user_id;
            }
            if (!empty($setting)) {
                $this->request->data['UserSetting']['setting'] = $setting;
            }
            // force our user's ID as the user ID in all cases
            $userSetting = array(
                'user_id' => $this->Auth->user('id')
            );
            if (!empty($this->request->data['UserSetting']['user_id']) && is_numeric($this->request->data['UserSetting']['user_id'])) {
                $user = $this->UserSetting->User->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('User.id' => $this->request->data['UserSetting']['user_id']),
                    'fields' => array('User.org_id')
                ));
                if (
                    $this->_isSiteAdmin() ||
                    ($this->_isAdmin() && ($user['User']['org_id'] == $this->Auth->user('org_id')))
                ) {
                    $userSetting['user_id'] = $this->request->data['UserSetting']['user_id'];
                }
            }
            if (empty($this->request->data['UserSetting']['setting']) || !isset($this->request->data['UserSetting']['setting'])) {
                throw new MethodNotAllowedException(__('This endpoint expects both a setting and a value to be set.'));
            }
            if (!$this->UserSetting->checkSettingValidity($this->request->data['UserSetting']['setting'])) {
                throw new MethodNotAllowedException(__('Invalid setting.'));
            }
            $settingPermCheck = $this->UserSetting->checkSettingAccess($this->Auth->user(), $this->request->data['UserSetting']['setting']);
            if ($settingPermCheck !== true) {
                throw new MethodNotAllowedException(__('This setting is restricted and requires the following permission(s): %s', $settingPermCheck));
            }
            $userSetting['setting'] = $this->request->data['UserSetting']['setting'];
            if ($this->request->data['UserSetting']['value'] !== '') {
                $userSetting['value'] = json_encode(json_decode($this->request->data['UserSetting']['value'], true));
            } else {
                $userSetting['value'] = '';
            }
            $existingSetting = $this->UserSetting->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                    'UserSetting.user_id' => $userSetting['user_id'],
                    'UserSetting.setting' => $userSetting['setting']
                )
            ));
            if (empty($existingSetting)) {
                $this->UserSetting->create();
            } else {
                $userSetting['id'] = $existingSetting['UserSetting']['id'];
            }
            // save the setting
            $result = $this->UserSetting->save(array('UserSetting' => $userSetting));
            if ($result) {
                // if we've managed to save our setting
                if ($this->_isRest()) {
                    // if we are dealing with an API request
                    $userSetting = $this->UserSetting->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('UserSetting.id' => $this->UserSetting->id)
                    ));
                    return $this->RestResponse->viewData($userSetting, $this->response->type());
                } else {
                    // if we are dealing with a UI request, redirect the user to the user view with the proper flash message
                    $this->Flash->success(__('Setting saved.'));
                    $this->redirect(array('controller' => 'user_settings', 'action' => 'index', $this->Auth->User('id')));
                }
            } else {
                // if we've failed saving our setting
                if ($this->_isRest()) {
                    // if we are dealing with an API request
                    return $this->RestResponse->saveFailResponse('UserSettings', 'add', false, $this->UserSetting->validationErrors, $this->response->type());
                } else {
                    /*
                     * if we are dealing with a UI request, simply set an error in a flash message
                     * and render the view of this endpoint, pre-populated with the submitted values.
                     */
                    $this->Flash->error(__('Setting could not be saved.'));
                }
            }
        }
        if ($this->_isRest()) {
            // GET request via the API should describe the endpoint
            return $this->RestResponse->describe('UserSettings', 'setSetting', false, $this->response->type());
        } else {
            // load the valid settings from the model
            $validSettings = $this->UserSetting->validSettings;
            if ($this->_isSiteAdmin()) {
                $users = $this->UserSetting->User->find('list', array(
                    'recursive' => -1,
                    'fields' => array('User.id', 'User.email')
                ));
            } else if ($this->_isAdmin()) {
                $users = $this->UserSetting->User->find('list', array(
                    'recursive' => -1,
                    'conditions' => array('User.org_id' => $this->Auth->user('org_id')),
                    'fields' => array('User.id', 'User.email')
                ));
            } else {
                $users = array($this->Auth->user('id') => $this->Auth->user('email'));
            }
            if (!empty($user_id) && $this->request->is('get')) {
                $this->request->data['UserSetting']['user_id'] = $user_id;
            }
            $this->set('setting', $setting);
            $this->set('users', $users);
            $this->set('validSettings', $validSettings);
        }
    }

    public function getSetting($user_id, $setting)
    {
        if (!$this->UserSetting->checkSettingValidity($setting)) {
            throw new MethodNotAllowedException(__('Invalid setting.'));
        }
        $userSetting = $this->UserSetting->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'UserSetting.user_id' => $user_id,
                'UserSetting.setting' => $setting
            ),
            'contain' => array('User.id', 'User.org_id')
        ));
        $checkAccess = $this->UserSetting->checkAccess($this->Auth->user(), $userSetting, $user_id);
        if (empty($checkAccess)) {
            throw new MethodNotAllowedException(__('Invalid setting.'));
        }
        if (!empty($userSetting)) {
            $userSetting = json_encode($userSetting['UserSetting']['value']);
        } else {
            $userSetting = '[]';
        }
        return $this->RestResponse->viewData($userSetting, $this->response->type(), false, true);
    }

    public function delete($id = false)
    {
        if ($this->request->is('get') && $this->_isRest()) {
            /*
             * GET request via the API should describe the endpoint
             * Unlike with the add() endpoint, we want to run this check before doing anything else,
             * in order to allow us to reach this endpoint without passing a valid ID
             */
            return $this->RestResponse->describe('UserSettings', 'delete', false, $this->response->type());
        }
        // check if the ID is valid and whether a user setting with the given ID exists
        if (empty($id) || !is_numeric($id)) {
            throw new InvalidArgumentException(__('Invalid ID passed.'));
        }
        $userSetting = $this->UserSetting->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'UserSetting.id' => $id
            ),
            'contain' => array('User.id', 'User.org_id')
        ));
        if (empty($userSetting)) {
            throw new NotFoundException(__('Invalid user setting.'));
        }
        $checkAccess = $this->UserSetting->checkAccess($this->Auth->user(), $userSetting);
        if (!$checkAccess) {
            throw new NotFoundException(__('Invalid user setting.'));
        }
        $settingPermCheck = $this->UserSetting->checkSettingAccess($this->Auth->user(), $userSetting['UserSetting']['setting']);
        if ($settingPermCheck !== true) {
            throw new MethodNotAllowedException(__('This setting is restricted and requires the following permission(s): %s', $settingPermCheck));
        }
        if ($this->request->is('post') || $this->request->is('delete')) {
            // Delete the setting that we were after.
            $result = $this->UserSetting->delete($userSetting['UserSetting']['id']);
            if ($result) {
                // set the response for both the UI and API
                $message = __('Setting deleted.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('UserSettings', 'delete', $id, $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                }
            } else {
                // set the response for both the UI and API
                $message = __('Setting could not be deleted.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('UserSettings', 'delete', $id, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                }
            }
            /*
             * The API responses stopped executing this function and returned a serialised response to the user.
             * For UI users, redirect to where they issued the request from.
             */
            $this->redirect($this->referer());
        } else {
            throw new MethodNotAllowedException(__('Expecting POST or DELETE request.'));
        }
    }
}
