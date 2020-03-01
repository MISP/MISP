<?php
App::uses('AppController', 'Controller');

class DashboardsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions = array('renderWidget', 'updateSettings', 'getForm');
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999
    );

    public function index()
    {
        $this->loadModel('UserSetting');
        $params = array(
            'conditions' => array(
                'UserSetting.user_id' => $this->Auth->user('id'),
                'UserSetting.setting' => 'dashboard'
            )
        );
        $userSettings = $this->UserSetting->find('first', $params);
        if (empty($userSettings)) {
            $userSettings = array(
                'UserSetting' => array(
                    'setting' => 'dashboard',
                    'value' => array(
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
                    )
                )
            );
        }
        $widgets = array();
        foreach ($userSettings['UserSetting']['value'] as $widget) {
            $dashboardWidget = $this->Dashboard->loadWidget($this->Auth->user(), $widget['widget']);
            $widget['width'] = $dashboardWidget->width;
            $widget['height'] = $dashboardWidget->height;
            $widget['title'] = $dashboardWidget->title;
            $widgets[] = $widget;
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
                $data['widget_options'] = $this->Dashboard->loadAllWidgets();
            } else {
                $dashboardWidget = $this->Dashboard->loadWidget($this->Auth->user(), $data['widget']);
                $data['description'] = empty($dashboardWidget->description) ? '' : $dashboardWidget->description;
                $data['params'] = empty($dashboardWidget->params) ? array() : $dashboardWidget->params;
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
            if (!isset($this->request->data['value'])) {
                throw new InvalidArgumentException(__('No setting data found.'));
            }
            $data = array(
                'UserSetting' => array(
                    'user_id' => $this->Auth->user('id'),
                    'setting' => 'dashboard',
                    'value' => $this->request->data['value']
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

    public function renderWidget($force = false)
    {
        if ($this->request->is('post')) {
            if (empty($this->request->data['data'])) {
                $this->request->data = array('data' => $this->request->data);

            }
            if (empty($this->request->data['data'])) {
                throw new MethodNotAllowedException(__('You need to specify the widget to use along with the configuration.'));
            }
            $value = $this->request->data['data'];
            $dashboardWidget = $this->Dashboard->loadWidget($this->Auth->user(), $value['widget']);
            $this->layout = false;
            $this->set('title', $dashboardWidget->title);
            $redis = $this->Dashboard->setupRedis();
            $org_scope = $this->_isSiteAdmin() ? 0 : $this->Auth->user('org_id');
            $lookup_hash = hash('sha256', $value['widget'] . $value['config']);
            $data = $redis->get('misp:dashboard:' . $org_scope . ':' . $lookup_hash);
            if (empty($data)) {
                $data = $dashboardWidget->handler($this->Auth->user(), json_decode($value['config'], true));
                $redis->set('misp:dashboard:' . $org_scope . ':' . $lookup_hash, json_encode(array('data' => $data)));
                $redis->expire('misp:dashboard:' . $org_scope . ':' . $lookup_hash, 60);
            } else {
                $data = json_decode($data, true)['data'];
            }
            $this->set('data', $data);
            $this->render('/Dashboards/Widgets/' . $dashboardWidget->render);
        } else {
            throw new MethodNotAllowedException(__('This endpoint can only be reached via POST requests.'));
        }
    }
}
