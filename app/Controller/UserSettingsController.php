<?php

/*
 *
 * Feature developed as part of a training given by CIRCL in Luxembourg on 26/09/2019
 * Verbose comments for educational purposes only
 *
 */

App::uses('AppController', 'Controller');

/**
 * @property UserSetting $UserSetting
 */
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
            'User' => array(
                'fields' => array('id', 'email', 'org_id'),
                'Organisation' => array(
                    'fields' => array('id', 'name', 'uuid')
                )
            )
        )
    );

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions[] = 'eventIndexColumnToggle';
        $this->Security->unlockedActions[] = 'setTheme';
        $this->Security->unlockedActions[] = 'setHomePage';
        if ($this->action === 'setSetting') {
            $this->Security->unlockedFields = array('value', 'value_select');
        }
    }

    public function index()
    {
        $filterData = array(
            'request' => $this->request,
            'paramArray' => array('setting', 'quickFilter', 'user_id', 'sort', 'direction', 'page', 'limit'),
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
        // Filter bar for Overmind theme
        if (!empty($filters['quickFilter'])) {
            $conditions['AND'][] = array(
                'UserSetting.setting LIKE' => '%' . $filters['quickFilter'] . '%',
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
                $orgUserConditions = array('User.org_id' => $this->Auth->user('org_id'));
                // An org admin must not see a site admin's settings.
                $siteAdminRoleIds = $this->UserSetting->User->getSiteAdminRoleIds();
                if (!empty($siteAdminRoleIds)) {
                    $orgUserConditions['NOT'] = array('User.role_id' => $siteAdminRoleIds);
                }
                $conditions['AND'][] = array(
                    'UserSetting.user_id' => $this->UserSetting->User->find(
                        'list', array(
                            'recursive' => -1,
                            'conditions' => $orgUserConditions,
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
        // Do not show internal settings
        if (!$this->_isSiteAdmin()) {
            $conditions['AND'][] = ['NOT' => ['UserSetting.setting' => $this->UserSetting->getInternalSettingNames()]];
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
            $authUser = $this->Auth->user();
            foreach ($data as $k => $v) {
                if (!empty(UserSetting::VALID_SETTINGS[$v['UserSetting']['setting']])) {
                    $data[$k]['UserSetting']['restricted'] = empty(UserSetting::VALID_SETTINGS[$v['UserSetting']['setting']]['restricted']) ? '' : UserSetting::VALID_SETTINGS[$v['UserSetting']['setting']]['restricted'];
                } else {
                    $data[$k]['UserSetting']['restricted'] = array();
                }
                $data[$k]['UserSetting']['_canDelete'] = (
                    $this->UserSetting->checkAccess($authUser, $v)
                    && $this->UserSetting->checkSettingAccess($authUser, $v['UserSetting']['setting']) === true
                );
            }
            $this->set('data', $data);
            $this->set('context', empty($context) ? 'null' : $context);
        }
    }

    public function view($id)
    {
        if (!$this->_isRest()) {
            throw new BadRequestException("This endpoint is accessible just by REST requests.");
        }
        // check if the ID is valid and whether a user setting with the given ID exists
        if (empty($id) || !is_numeric($id)) {
            throw new BadRequestException(__('Invalid ID passed.'));
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
        unset($userSetting['User']);
        return $this->RestResponse->viewData($userSetting, $this->response->type());
    }

    public function setSetting($user_id = false, $setting = false)
    {
        if (!empty($setting)) {
            if (!$this->UserSetting->checkSettingValidity($setting) || $this->UserSetting->isInternal($setting)) {
                throw new MethodNotAllowedException(__('Invalid setting.'));
            }
            $settingPermCheck = $this->UserSetting->checkSettingAccess($this->Auth->user(), $setting);
            if ($settingPermCheck !== true) {
                throw new MethodNotAllowedException(__('This setting is restricted and requires the following permission(s): %s', $settingPermCheck));
            }
        }
        if (!empty($user_id) && !empty($setting) && !$this->_isRest()) {
            $current_setting = $this->UserSetting->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                    'UserSetting.user_id' => $user_id,
                    'UserSetting.setting' => $setting
                )
            ));
            if (!empty($current_setting)) {
                $this->set('current_setting', $current_setting['UserSetting']['value']);
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
            $result = $this->UserSetting->setSetting($this->Auth->user(), $this->request->data);
            if ($result) {
                // if we've managed to save our setting
                if ($this->_isRest()) {
                    // if we are dealing with an API request
                    $userSetting = $this->UserSetting->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('UserSetting.id' => $this->UserSetting->id)
                    ));
                    return $this->RestResponse->viewData($userSetting['UserSetting'], $this->response->type());
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
                     * and render the view of this endpoint, prepopulated with the submitted values.
                     */
                    $this->Flash->error(__('Setting could not be saved.'));
                }
            }
        }
        if ($this->_isRest()) {
            // GET request via the API should describe the endpoint
            return $this->RestResponse->describe('UserSettings', 'setSetting', false, $this->response->type());
        }

        // load the valid settings from the model
        if ($this->_isSiteAdmin()) {
            $users = $this->UserSetting->User->find('list', array(
                'fields' => array('User.id', 'User.email')
            ));
        } else if ($this->_isAdmin()) {
            $users = $this->UserSetting->User->find('list', array(
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
        $this->set('validSettings', $this->UserSetting->settingPlaceholders($this->Auth->user()));
        $this->set('title_for_layout', __('Set User Setting'));
        if ($this->theme === 'Overmind') {
            $this->layout = false;
        }
    }

    public function getSetting($userId = null, $setting = null)
    {
        if ($this->request->is('post')) {
            if (empty($this->request->data['setting'])) {
                throw new BadRequestException("No setting name provided.");
            }
            $setting = $this->request->data['setting'];
            $userId = $this->request->data['user_id'] ?? $this->Auth->user('id');
        } else {
            if (empty($userId) || empty($setting)) {
                throw new BadRequestException("No setting name or user ID provided.");
            }
        }

        if (!$this->UserSetting->checkSettingValidity($setting) || $this->UserSetting->isInternal($setting)) {
            throw new NotFoundException(__('Invalid setting.'));
        }

        $userSetting = $this->UserSetting->find('first', array(
            'recursive' => -1,
            'conditions' => [
                'UserSetting.user_id' => $userId,
                'UserSetting.setting' => $setting,
            ],
            'contain' => array('User.id', 'User.org_id')
        ));

        if (empty($userSetting)) {
            throw new NotFoundException(__('Invalid setting.'));
        }

        $checkAccess = $this->UserSetting->checkAccess($this->Auth->user(), $userSetting, $userId);
        if (!$checkAccess) {
            throw new NotFoundException(__('Invalid setting.'));
        }
        return $this->RestResponse->viewData($userSetting['UserSetting'], $this->response->type());
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

        if (!$this->request->is('post') && !$this->request->is('delete')) {
            throw new MethodNotAllowedException(__('Expecting POST or DELETE request.'));
        }

        if (empty($id)) {
            if (empty($this->request->data['setting'])) {
                throw new BadRequestException("No setting name to delete provided.");
            }
            $conditions = ['UserSetting.setting' => $this->request->data['setting']];
            if (!empty($this->request->data['user_id'])) {
                $conditions['UserSetting.user_id'] = $this->request->data['user_id'];
            } else {
                $conditions['UserSetting.user_id'] = $this->Auth->user('id'); // current user
            }
        } else if (is_numeric($id)) {
            $conditions = ['UserSetting.id' => $id];
        } else {
            throw new BadRequestException(__('Invalid ID passed.'));
        }

        $userSetting = $this->UserSetting->find('first', array(
            'recursive' => -1,
            'conditions' => $conditions,
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
        // Delete the setting that we were after.
        $result = $this->UserSetting->delete($userSetting['UserSetting']['id']);
        if ($result) {
            // set the response for both the UI and API
            $message = __('Setting deleted.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('UserSettings', 'delete', $userSetting['UserSetting']['id'], $this->response->type(), $message);
            } else {
                $this->Flash->success($message);
            }
        } else {
            // set the response for both the UI and API
            $message = __('Setting could not be deleted.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('UserSettings', 'delete', $userSetting['UserSetting']['id'], $message, $this->response->type());
            } else {
                $this->Flash->error($message);
            }
        }
        /*
         * The API responses stopped executing this function and returned a serialised response to the user.
         * For UI users, redirect to where they issued the request from.
         */
        $this->redirect($this->referer());
    }

    public function deleteSelection($id = false)
    {
        $authUser = $this->Auth->user();

        if ($this->request->is(array('post', 'put', 'delete'))) {
            $idList = $this->request->data['UserSetting']['id'] ?? $id;
            if (!is_array($idList)) {
                $idList = is_numeric($idList) ? array($idList) : json_decode($idList, true);
            }
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }

            $deleted = 0;
            $failed = 0;
            $blocked = 0;
            foreach ($idList as $settingId) {
                if (!is_numeric($settingId)) {
                    $failed++;
                    continue;
                }
                $userSetting = $this->UserSetting->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('UserSetting.id' => $settingId),
                    'contain' => array('User.id', 'User.org_id')
                ));
                if (empty($userSetting)) {
                    $failed++;
                    continue;
                }
                if (
                    !$this->UserSetting->checkAccess($authUser, $userSetting) ||
                    $this->UserSetting->checkSettingAccess($authUser, $userSetting['UserSetting']['setting']) !== true
                ) {
                    $blocked++;
                    continue;
                }
                if ($this->UserSetting->delete($userSetting['UserSetting']['id'])) {
                    $deleted++;
                } else {
                    $failed++;
                }
            }

            $messages = array();
            if ($deleted) {
                $messages[] = __n('%s setting deleted.', '%s settings deleted.', $deleted, $deleted);
            }
            if ($blocked) {
                $messages[] = __n('%s setting was skipped (insufficient permissions).', '%s settings were skipped (insufficient permissions).', $blocked, $blocked);
            }
            if ($failed) {
                $messages[] = __n('%s setting could not be deleted.', '%s settings could not be deleted.', $failed, $failed);
            }
            $message = trim(implode(' ', $messages));

            if ($this->_isRest()) {
                if ($deleted) {
                    return $this->RestResponse->saveSuccessResponse('UserSettings', 'deleteSelection', $id, $this->response->type(), $message);
                }
                return $this->RestResponse->saveFailResponse('UserSettings', 'deleteSelection', false, $message, $this->response->type());
            }

            if ($deleted && !$blocked && !$failed) {
                $this->Flash->success($message);
            } elseif ($deleted) {
                $this->Flash->warning($message);
            } else {
                $this->Flash->error($message ?: __('No settings were deleted.'));
            }
            return $this->redirect(array('action' => 'index'));
        }

        // GET → build the confirmation modal.
        $idList = is_numeric($id) ? array($id) : json_decode($id, true);
        if (empty($idList)) {
            throw new NotFoundException(__('Invalid input.'));
        }
        $userSettings = $this->UserSetting->find('all', array(
            'recursive' => -1,
            'conditions' => array('UserSetting.id' => $idList),
            'contain' => array('User.id', 'User.org_id', 'User.email')
        ));
        $deletable = array();
        $blocked = array();
        foreach ($userSettings as $userSetting) {
            $label = $userSetting['UserSetting']['setting'];
            if (!empty($userSetting['User']['email'])) {
                $label .= ' (' . $userSetting['User']['email'] . ')';
            }
            if (
                !$this->UserSetting->checkAccess($authUser, $userSetting) ||
                $this->UserSetting->checkSettingAccess($authUser, $userSetting['UserSetting']['setting']) !== true
            ) {
                $blocked[] = array('id' => $userSetting['UserSetting']['id'], 'label' => $label);
            } else {
                $deletable[] = array('id' => $userSetting['UserSetting']['id'], 'label' => $label);
            }
        }

        // Only the entries the user may actually delete are submitted.
        $deletableIds = array_map(function ($entry) {
            return $entry['id'];
        }, $deletable);
        $this->request->data['UserSetting']['id'] = json_encode($deletableIds);
        $this->set('idArray', $idList);
        $this->set('deletable', $deletable);
        $this->set('blocked', $blocked);
        $this->layout = false;
        $this->render('/UserSettings/ajax/user_setting_delete_confirmation');
    }

    public function setHomePage()
    {
        if ($this->request->is('post')) {
            if (isset($this->request->data['UserSetting'])) {
                $this->request->data = $this->request->data['UserSetting'];
            }
            if (!isset($this->request->data['path'])) {
                $this->request->data = array('path' => $this->request->data);
            }
            if (empty($this->request->data['path'])) {
                throw new InvalidArgumentException(__('No path POSTed.'));
            }
            $setting = array(
                'UserSetting' => array(
                    'user_id' => $this->Auth->user('id'),
                    'setting' => 'homepage',
                    'value' => ['path' => $this->request->data['path']],
                )
            );
            // Always persist through setSetting() so the homepage validation (validate_homepage,
            // which requires the path to start with '/') and the access/self-management checks run.
            // The Overmind theme previously called setSettingInternal() directly, skipping validation
            // and allowing an arbitrary path - e.g. an XSS payload - to be stored as the homepage.
            $result = $this->UserSetting->setSetting($this->Auth->user(), $setting);
            return $this->RestResponse->saveSuccessResponse('UserSettings', 'setHomePage', false, 'json', 'Homepage set to ' . $this->request->data['path']);
        } else {
            $this->layout = false;
        }
    }

    public function eventIndexColumnToggle($columnName)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('Expecting POST request.'));
        }

        $hideColumns = $this->UserSetting->getValueForUser($this->Auth->user()['id'], 'event_index_hide_columns');
        if ($hideColumns === null) {
            $hideColumns = [];
        }

        if (($key = array_search($columnName, $hideColumns, true)) !== false) {
            unset($hideColumns[$key]);
            $hideColumns = array_values($hideColumns);
        } else {
            $hideColumns[] = $columnName;
        }

        $setting = [
            'UserSetting' => [
                'user_id' => $this->Auth->user()['id'],
                'setting' => 'event_index_hide_columns',
                'value' => $hideColumns,
            ]
        ];
        $this->UserSetting->setSetting($this->Auth->user(), $setting);
        return $this->RestResponse->saveSuccessResponse('UserSettings', 'eventIndexColumnToggle', false, 'json', 'Column visibility switched');
    }

    /**
     * Toggle UI theme setting for the current user
     * Provides a quick way to enable alternate UIs without navigating to settings
     */
    public function setTheme($theme)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('Expecting POST request.'));
        }

        $userId = $this->Auth->user('id');
        $validThemes = array_flip($this->UserSetting::VALID_SETTINGS['ui_theme']['options']);
        if (!isset($validThemes[$theme])) {
            throw new BadRequestException(__('Invalid theme option provided.'));
        }

        $result = $this->UserSetting->setSettingInternal(
            $userId, 'ui_theme', $theme
        );

        if ($result) {
            $message = __('%s theme set. The page will now reload.', $theme);
            return $this->RestResponse->saveSuccessResponse('UserSettings', 'setTheme', false, 'json', $message);
        } else {
            $message = __('Failed to set %s theme.', $theme);
            return $this->RestResponse->saveFailResponse('UserSettings', 'setTheme', false, $message, 'json');
        }
    }

    /**
     * Persist the event-template instantiation form's view-mode preference.
     * Single-page (`all`) shows every section at once; `wizard` shows one
     * section at a time with prev/next navigation. The setting is read by
     * EventTemplatesController on next page load.
     */
    public function setEventTemplateUserFormMode($mode)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('Expecting POST request.'));
        }
        $valid = array_flip($this->UserSetting::VALID_SETTINGS['event_template_user_form_mode']['options']);
        if (!isset($valid[$mode])) {
            throw new BadRequestException(__('Invalid view mode.'));
        }
        $userId = $this->Auth->user('id');
        $result = $this->UserSetting->setSettingInternal(
            $userId, 'event_template_user_form_mode', $mode
        );
        if ($result) {
            return $this->RestResponse->saveSuccessResponse(
                'UserSettings', 'setEventTemplateUserFormMode', false, 'json',
                __('Form view mode set to %s.', $mode)
            );
        }
        return $this->RestResponse->saveFailResponse(
            'UserSettings', 'setEventTemplateUserFormMode', false,
            __('Failed to persist form view mode.'), 'json'
        );
    }
}
