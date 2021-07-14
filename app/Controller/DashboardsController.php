<?php
App::uses('AppController', 'Controller');

/**
 * @property Dashboard $Dashboard
 */
class DashboardsController extends AppController
{
    public $components = array('Session', 'RequestHandler');
    public $helpers = array('ScopedCSS');

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions = array_merge(array('renderWidget', 'getForm'), $this->Security->unlockedActions);
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999
    );

    public function index($template_id = false)
    {
        $this->loadModel('UserSetting');
        if (empty($template_id)) {
            $params = array(
                'conditions' => array(
                    'UserSetting.user_id' => $this->Auth->user('id'),
                    'UserSetting.setting' => 'dashboard'
                )
            );
            $userSettings = $this->UserSetting->find('first', $params);
        } else {
            $dashboardTemplate = $this->Dashboard->getDashboardTemplate($this->Auth->user(), $template_id);
            if (empty($dashboardTemplate)) {
                throw new NotFoundException(__('Invalid dashboard template.'));
            }
        }
        if (empty($userSettings) && empty($dashboardTemplate)) {
            $dashboardTemplate = $this->Dashboard->getDashboardTemplate($this->Auth->user());
        }
        if (empty($userSettings)) {
            if (empty($dashboardTemplate)) {
                $value = array(
                    array(
                        'widget' => 'MispStatusWidget',
                        'config' => array(
                        ),
                        'position' => array(
                            'x' => 0,
                            'y' => 0,
                            'width' => 2,
                            'height' => 2
                        )
                    )
                );
            } else {
                $value = $dashboardTemplate['Dashboard']['value'];
                if (!is_array($value)) {
                    $value = json_decode($value, true);
                }
            }
            $userSettings = array(
                'UserSetting' => array(
                    'setting' => 'dashboard',
                    'value' => $value
                )
            );
        }
        $widgets = array();
        foreach ($userSettings['UserSetting']['value'] as $widget) {
            try {
                $dashboardWidget = $this->Dashboard->loadWidget($this->Auth->user(), $widget['widget']);
                $widget['width'] = $dashboardWidget->width;
                $widget['height'] = $dashboardWidget->height;
                $widget['title'] = $dashboardWidget->title;
                $widgets[] = $widget;
            } catch (Exception $e) {
                // continue, we just don't load the widget
            }
        }
        $this->layout = 'dashboard';
        $this->set('widgets', $widgets);
    }

    public function getForm($action = 'edit')
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $data = $this->request->data;
            if ($action === 'edit' && !isset($data['widget'])) {
                throw new InvalidArgumentException(__('No widget name passed.'));
            }
            if (empty($data['config'])) {
                $data['config'] = '';
            }
            if ($action === 'add') {
                $data['widget_options'] = $this->Dashboard->loadAllWidgets($this->Auth->user());
            } else {
                $dashboardWidget = $this->Dashboard->loadWidget($this->Auth->user(), $data['widget']);
                $data['description'] = empty($dashboardWidget->description) ? '' : $dashboardWidget->description;
                $data['params'] = empty($dashboardWidget->params) ? array() : $dashboardWidget->params;
                $data['params'] = array_merge($data['params'], array('widget_config' => __('Configuration of the widget that will be passed to the render. Check the view for more information')));
                $data['params'] = array_merge(array('alias' => __('Alias to use as the title of the widget')), $data['params']);
            }
            $this->set('data', $data);
            $this->layout = false;
            $this->render($action);
        }
    }

    public function updateSettings()
    {
        if ($this->request->is('post')) {
            $this->UserSetting = ClassRegistry::init('UserSetting');
            if (!isset($this->request->data['Dashboard']['value'])) {
                throw new InvalidArgumentException(__('No setting data found.'));
            }
            $data = array(
                'UserSetting' => array(
                    'user_id' => $this->Auth->user('id'),
                    'setting' => 'dashboard',
                    'value' => $this->request->data['Dashboard']['value']
                )
            );
            $result = $this->UserSetting->setSetting($this->Auth->user(), $data);
            if ($result) {
                return $this->RestResponse->saveSuccessResponse('Dashboard', 'updateSettings', false, false, __('Settings updated.'));
            }
            return $this->RestResponse->saveFailResponse('Dashboard', 'updateSettings', false, $this->UserSetting->validationErrors, $this->response->type());
        }
    }

    public function getEmptyWidget($widget, $k = 1)
    {
        $dashboardWidget = $this->Dashboard->loadWidget($this->Auth->user(), $widget);
        if (empty($dashboardWidget)) {
            throw new NotFoundException(__('Invalid widget.'));
        }
        $this->layout = false;
        $widget = array(
            'config' => isset($dashboardWidget->config) ? $dashboardWidget->height : '',
            'title' => $dashboardWidget->title,
            'alias' => isset($dashboardWidget->alias) ? $dashboardWidget->alias : $dashboardWidget->title,
            'widget' => $widget
        );
        $this->set('k', $k);
        $this->set('widget', $widget);
    }

    public function renderWidget($widget_id, $force = false)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint can only be reached via POST requests.'));
        }

        @session_write_close(); // allow concurrent AJAX requests (session hold lock by default)

        if (empty($this->request->data['data'])) {
            $this->request->data = array('data' => $this->request->data);
        }
        if (empty($this->request->data['data'])) {
            throw new MethodNotAllowedException(__('You need to specify the widget to use along with the configuration.'));
        }
        $value = $this->request->data['data'];
        $valueConfig = json_decode($value['config'], true);
        $dashboardWidget = $this->Dashboard->loadWidget($this->Auth->user(), $value['widget']);

        $redis = $this->Dashboard->setupRedis();
        $org_scope = $this->_isSiteAdmin() ? 0 : $this->Auth->user('org_id');
        $lookup_hash = hash('sha256', $value['widget'] . $value['config']);
        $cacheKey = 'misp:dashboard:' . $org_scope . ':' . $lookup_hash;
        $data = $redis->get($cacheKey);
        if (!isset($dashboardWidget->cacheLifetime)) {
            $dashboardWidget->cacheLifetime = false;
        }
        if (empty($dashboardWidget->cacheLifetime) || empty($data)) {
            $data = $dashboardWidget->handler($this->Auth->user(), $valueConfig);
            if (!empty($dashboardWidget->cacheLifetime)) {
                $redis->setex($cacheKey, $dashboardWidget->cacheLifetime, json_encode(array('data' => $data)));
            }
        } else {
            $data = json_decode($data, true)['data'];
        }
        $config = array(
            'render' => $dashboardWidget->render,
            'autoRefreshDelay' => empty($dashboardWidget->autoRefreshDelay) ? false : $dashboardWidget->autoRefreshDelay,
            'widget_config' => empty($valueConfig['widget_config']) ? array() : $valueConfig['widget_config']
        );

        $this->layout = false;
        $this->set('title', $dashboardWidget->title);
        $this->set('widget_id', $widget_id);
        $this->set('data', $data);
        $this->set('config', $config);
        $this->render('widget_loader');
    }

    public function import()
    {
        if ($this->request->is('post')) {
            if (!empty($this->request->data['Dashboard'])) {
                $this->request->data = json_decode($this->request->data['Dashboard']['value'], true);
            }
            if (!empty($this->request->data['UserSetting'])) {
                $this->request->data = $this->request->data['UserSetting']['value'];
            }
            $result = $this->Dashboard->import($this->Auth->user(), $this->request->data);
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Dashboard', 'import', false, false, __('Settings updated.'));
                }
                return $this->RestResponse->saveFailResponse('Dashboard', 'import', false, __('Settings could not be updated.'), $this->response->type());
            } else {
                if ($result) {
                    $this->Flash->success(__('Settings updated.'));
                } else {
                    $this->Flash->error(__('Settings could not be updated.'));
                }
                $this->redirect($this->baseurl . '/dashboards');
            }
        }
        $this->layout = false;
    }

    public function export()
    {
        $data = $this->Dashboard->export($this->Auth->user());
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->set('data', $data);
            $this->layout = false;
        }
    }

    public function saveTemplate($update = false)
    {
        $this->loadModel('UserSetting');
        if (!empty($update)) {
            $conditions = array('Dashboard.id' => $update);
            if (Validation::uuid($update)) {
                $conditions = array('Dashboard.uuid' => $update);
            }
            $existingDashboard = $this->Dashboard->find('first', array(
                'recursive' => -1,
                'conditions' => $conditions
            ));
            if (
                empty($existingDashboard) ||
                (!$this->_isSiteAdmin() && $existingDashboard['Dashboard']['user_id'] != $this->Auth->user('id'))
            ) {
                throw new NotFoundException(__('Invalid dashboard template.'));
            }
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (isset($this->request->data['Dashboard'])) {
                $this->request->data = $this->request->data['Dashboard'];
            }
            $data = $this->request->data;
            if (empty($update)) { // save the template stored in user setting and make it persistent
                $data['value'] = $this->UserSetting->getSetting($this->Auth->user('id'), 'dashboard');
            }
            $result = $this->Dashboard->saveDashboardTemplate($this->Auth->user(), $data, $update);
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Dashboard', 'saveDashboardTemplate', false, false, __('Dashboard template updated.'));
                }
                return $this->RestResponse->saveFailResponse('Dashboard', 'import', false, __('Dashboard template could not be updated.'), $this->response->type());
            } else {
                if ($result) {
                    $this->Flash->success(__('Dashboard template updated.'));
                } else {
                    $this->Flash->error(__('Dashboard template could not be updated.'));
                }
                $this->redirect($this->baseurl . '/dashboards/listTemplates');
            }
        } else {
            $this->layout = false;
        }
        $this->loadModel('User');
        $permFlags = array(0 => __('Unrestricted'));
        foreach ($this->User->Role->permFlags as $perm_flag => $perm_data) {
            $permFlags[$perm_flag] = $perm_data['text'];
        }
        $options = array(
            'org_id' => (
                array(
                    0 => __('Unrestricted')
                ) + // avoid re-indexing
                $this->User->Organisation->find('list', array(
                    'fields' => array(
                        'Organisation.id', 'Organisation.name'
                    ),
                    'conditions' => array('Organisation.local' => 1)
                ))
            ),
            'role_id' => (
                array(
                    0 => __('Unrestricted')
                ) + // avoid re-indexing
                $this->User->Role->find('list', array(
                    'fields' => array(
                        'Role.id', 'Role.name'
                    )
                ))
            ),
            'role_perms' => $permFlags
        );
        if (!empty($update)) {
            $this->request->data = $existingDashboard;
        }
        $this->set('options', $options);
    }

    public function listTemplates()
    {
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $permission_flags = array();
            foreach ($this->Auth->user('Role') as $perm => $value) {
                if (strpos($perm, 'perm_') !== false && !empty($value)) {
                    $permission_flags[] = $perm;
                }
            }
            $conditions['AND'] = array(
                array(
                    'OR' => array(
                        'Dashboard.user_id' => $this->Auth->user('id'),
                        'AND' => array(
                            'Dashboard.selectable' => 1,
                            array(
                                'OR' => array(
                                    array('Dashboard.restrict_to_org_id' => $this->Auth->user('org_id')),
                                    array('Dashboard.restrict_to_org_id' => 0)
                                )
                            ),
                            array(
                                'OR' => array(
                                    array('Dashboard.restrict_to_role_id' => $this->Auth->user('role_id')),
                                    array('Dashboard.restrict_to_role_id' => 0)
                                )
                            ),
                            array(
                                'OR' => array(
                                    array('Dashboard.restrict_to_permission_flag' => $permission_flags),
                                    array('Dashboard.restrict_to_permission_flag' => 0)
                                )
                            )
                        )
                    )
                )
            );
        }
        if (!empty($this->passedArgs['value'])) {
            $conditions['AND'][] = array(
                'OR' => array(
                    'LOWER(Dashboard.name) LIKE' => '%' . strtolower(trim($this->passedArgs['value'])) . '%',
                    'LOWER(Dashboard.description) LIKE' => '%' . strtolower(trim($this->passedArgs['value'])) . '%',
                    'LOWER(Dashboard.uuid) LIKE' => strtolower(trim($this->passedArgs['value']))
                )
            );
        }
        $this->paginate['conditions'] = $conditions;
        if ($this->_isRest()) {
            $params = array(
                'conditions' => $conditions,
                'recursive' => -1
            );
            $paramsToPass = array('limit', 'page');
            foreach ($paramsToPass as $p) {
                if (!empty($this->passedArgs[$p])) {
                    $params[$p] = $this->passedArgs[$p];
                }
            }
            $data = $this->Dashboard->find('all', $params);
            foreach ($data as &$element) {
                $element['Dashboard']['value'] = json_decode($element['Dashboard']['value'], true);
            }
            return $this->RestResponse->viewData(
                $data,
                $this->response->type()
            );
        } else {
            $this->paginate['contain'] = array(
                'User.id', 'User.email'
            );
            $data = $this->paginate();
            foreach ($data as &$element) {
                $element['Dashboard']['value'] = json_decode($element['Dashboard']['value'], true);
                $widgets = array();
                foreach ($element['Dashboard']['value'] as $val) {
                    $widgets[$val['widget']] = 1;
                }
                $element['Dashboard']['widgets'] = array_keys($widgets);
                sort($element['Dashboard']['widgets']);
                if ($element['Dashboard']['user_id'] != $this->Auth->user('id')) {
                    $element['User']['email'] = '';
                }
            }
            $this->set('passedArgs', json_encode($this->passedArgs));
            $this->set('data', $data);
        }
    }

    public function deleteTemplate($id)
    {
        $conditions = array();
        if (Validation::uuid($id)) {
            $conditions['AND'][] = array('Dashboard.uuid' => $id);
        } else {
            $conditions['AND'][] = array('Dashboard.id' => $id);
        }
        if (!$this->_isSiteAdmin()) {
            $conditions['AND'][] = array('Dashboard.user_id' => $this->Auth->user('id'));
        }
        $dashboard = $this->Dashboard->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1
        ));
        if (empty($dashboard)) {
            throw new NotFoundException(__('Invalid dashboard template.'));
        }
        $this->Dashboard->delete($dashboard['Dashboard']['id']);
        $message = __('Dashboard template removed.');
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Dashboard', 'delete', $id, false, $message);
        } else {
            $this->Flash->success($message);
            $this->redirect($this->baseurl . '/dashboards/listTemplates');
        }
    }
}
