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
        $this->Security->unlockedActions[] = 'renderWidget';
        $this->Security->unlockedActions[] = 'getForm';
        if ($this->request->action === 'renderWidget') {
            $this->Security->doNotGenerateToken = true;
        }
    }

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999
    );

    public function index($template_id = false)
    {
        if (empty($template_id)) {
            $params = array(
                'conditions' => array(
                    'UserSetting.user_id' => $this->Auth->user('id'),
                    'UserSetting.setting' => 'dashboard'
                )
            );
            $userSettings = $this->User->UserSetting->find('first', $params);
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
        $this->set('widgets', $widgets);
    }

    public function getForm($action = 'edit')
    {
        if ($this->request->is(['post', 'put'])) {
            $data = $this->request->data;
            if (empty($data['config'])) {
                $data['config'] = '';
            }
            if (!empty($data['id']) && !preg_match('/^[\w\d_]+$/i', $data['id'])) {
                throw new BadRequestException(__('Invalid widget id provided.'));
            }
            if ($action === 'add') {
                $data['widget_options'] = $this->Dashboard->loadAllWidgets($this->Auth->user());
            } else if ($action === 'edit') {
                if (!isset($data['widget'])) {
                    throw new BadRequestException(__('No widget name passed.'));
                }
                $dashboardWidget = $this->Dashboard->loadWidget($this->Auth->user(), $data['widget']);
                $data['description'] = empty($dashboardWidget->description) ? '' : $dashboardWidget->description;
                $data['params'] = empty($dashboardWidget->params) ? array() : $dashboardWidget->params;
                $data['params'] = array_merge($data['params'], array('widget_config' => __('Configuration of the widget that will be passed to the render. Check the view for more information')));
                $data['params'] = array_merge(array('alias' => __('Alias to use as the title of the widget')), $data['params']);
            } else {
                throw new BadRequestException(__('Invalid action provided, just add or edit is supported.'));
            }
            $this->set('data', $data);
            $this->layout = false;
            $this->render($action);
        }
    }

    public function updateSettings()
    {
        if ($this->request->is('post')) {
            if (!isset($this->request->data['Dashboard']['value'])) {
                throw new InvalidArgumentException(__('No setting data found.'));
            }
            $data = array(
                'UserSetting' => array(
                    'setting' => 'dashboard',
                    'value' => $this->request->data['Dashboard']['value']
                )
            );
            $result = $this->User->UserSetting->setSetting($this->Auth->user(), $data);
            if ($result) {
                return $this->RestResponse->saveSuccessResponse('Dashboard', 'updateSettings', false, false, __('Settings updated.'));
            }
            return $this->RestResponse->saveFailResponse('Dashboard', 'updateSettings', false, $this->User->UserSetting->validationErrors, $this->response->type());
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
        $user = $this->_closeSession();

        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint can only be reached via POST requests.'));
        }

        if (empty($this->request->data['data'])) {
            $this->request->data = array('data' => $this->request->data);
        }
        if (empty($this->request->data['data'])) {
            throw new MethodNotAllowedException(__('You need to specify the widget to use along with the configuration.'));
        }
        $value = $this->request->data['data'];
        $valueConfig = $this->_jsonDecode($value['config']);
        $dashboardWidget = $this->Dashboard->loadWidget($user, $value['widget']);

        $cacheLifetime = $dashboardWidget->cacheLifetime ?? false;
        if ($cacheLifetime !== false) {
            $orgScope = $this->_isSiteAdmin() ? 0 : $user['org_id'];
            $lookupHash = sha1($value['widget'] . $value['config'], true);
            $cacheKey = "misp:dashboard:$orgScope:$lookupHash";

            $redis = RedisTool::init();
            $data = $redis->get($cacheKey);
            if (!empty($data)) {
                $data = RedisTool::deserialize($data);
            } else {
                $data = $dashboardWidget->handler($user, $valueConfig);
                $redis->setex($cacheKey, $cacheLifetime, RedisTool::serialize($data));
            }
        } else {
            $data = $dashboardWidget->handler($user, $valueConfig);
        }
        $renderer = method_exists($dashboardWidget, 'getRenderer') ? $dashboardWidget->getRenderer($valueConfig) : $dashboardWidget->render;
        $config = array(
            'render' => $renderer,
            'autoRefreshDelay' => empty($dashboardWidget->autoRefreshDelay) ? false : $dashboardWidget->autoRefreshDelay,
            'widget_config' => empty($valueConfig['widget_config']) ? array() : $valueConfig['widget_config']
        );

        if (!empty($this->request->params['named']['exportjson'])) {
            return $this->RestResponse->viewData($data);
        } else if (!empty($this->request->params['named']['exportcsv'])) {
            $csv = '';
            $toConvert = !empty($data) ? (!empty($data['data']) ? $data['data'] : $data) : [];
            if (!empty($toConvert)) {
                $firstElement = key($toConvert);
                if (is_string($firstElement)) {
                    foreach ($toConvert as $key => $value) {
                        $csv .= sprintf('%s,%s', $key, json_encode($value)) . PHP_EOL;
                    }
                } else { // second element is an array
                    $csv = array_map(function($row) {
                        $flattened = array_values(Hash::flatten($row));
                        $stringified = array_map('strval', $flattened);
                        $quotified = array_map(function($item) { return sprintf('"%s"', $item); }, $stringified);
                        return implode(',', $quotified);
                    }, $toConvert);
                    $rowKey = implode(',', array_map(function ($item) {
                        return sprintf('"%s"', $item);
                    }, array_map('strval', array_keys(Hash::flatten($toConvert[0])))));
                    $csv = $rowKey . PHP_EOL .  implode(PHP_EOL, array_values($csv));
                }
            }
            return $this->RestResponse->viewData($csv, 'text/csv', false, true);
        }

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
                $data['value'] = $this->User->UserSetting->getSetting($this->Auth->user('id'), 'dashboard');
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
        // load all widgets for internal use, won't be displayed to the user. Thus we circumvent the ACL on it.
        $accessible_widgets = array_keys($this->Dashboard->loadAllWidgets($this->Auth->user()));
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
                $temp = [];
                foreach ($element['Dashboard']['widgets'] as $widget) {
                    if (in_array($widget, $accessible_widgets)) {
                        $temp['allow'][] = $widget;
                    } else {
                        $temp['deny'][] = $widget;
                    }
                }
                $element['Dashboard']['widgets'] = $temp;
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
