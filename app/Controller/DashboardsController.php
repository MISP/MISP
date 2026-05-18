<?php
App::uses('AppController', 'Controller');

/**
 * Dashboard controller (v2). Mounted at /dashboards/* via CakePHP's
 * default routing.
 *
 * @property Dashboard $Dashboard
 */
class DashboardsController extends AppController
{
    public $components = array('Session', 'RequestHandler');
    public $uses = array('Dashboard', 'User');

    public function beforeFilter()
    {
        parent::beforeFilter();
        // POSTs carry widget data in their body — same CSRF posture
        // as the v1 dashboards endpoints.
        foreach (array('renderWidget', 'updateSettings') as $a) {
            $this->Security->unlockedActions[] = $a;
        }
        if (in_array($this->request->action, array('renderWidget', 'updateSettings'), true)) {
            $this->Security->doNotGenerateToken = true;
        }
    }

    public function index()
    {
        App::uses('LayoutFixup', 'Lib/Dashboard/Tools');
        // Layout priority chain:
        //   1. If the user has a UserSetting:dashboard row (even with
        //      an empty array as the value), use that — a user who
        //      explicitly cleared their dashboard should NOT have a
        //      default template silently re-imposed on next visit.
        //   2. Else look up the org/role/permission-restricted default
        //      template via Dashboard::getDashboardTemplate, json_decode
        //      its `value` field, and use that.
        //   3. Else hand the view an empty array — the view renders
        //      the empty-state element ("No widgets yet").
        // On-read fix-ups (DD-05) normalise per-widget shape regardless
        // of source: width/height → w/h, instance_id minted if missing.
        // updateSettings writes go through the same path so persisted
        // shape is canonical. Top-level stays bare-array (DD-05).
        $user = $this->Auth->user();
        // getValueForUser distinguishes "row exists with empty value"
        // (returns []) from "no row at all" (returns null). getSetting
        // collapses both to [] which would silently re-impose the
        // default template on a user who'd cleared their dashboard.
        $saved = $this->User->UserSetting->getValueForUser($user['id'], 'dashboard');
        if (is_array($saved)) {
            $widgets = LayoutFixup::applyReadFixups($saved);
        } else {
            $widgets = array();
            $template = $this->Dashboard->getDashboardTemplate($user);
            if (!empty($template['Dashboard']['value'])) {
                $decoded = json_decode($template['Dashboard']['value'], true);
                if (is_array($decoded)) {
                    $widgets = LayoutFixup::applyReadFixups($decoded);
                }
            }
        }

        // REST clients get the layout payload as JSON via the
        // RestResponse component. Web UI falls through to
        // View/Dashboards/index.ctp under Layouts/dashboard.ctp.
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($widgets, $this->response->type());
        }

        $this->layout = 'dashboard';
        $this->set('title_for_layout', __('Dashboard'));
        $this->set('widgets', $widgets);
    }

    /**
     * Persist the user's dashboard layout. Mirrors v1's
     * `DashboardsController::updateSettings` contract so REST clients
     * written against v1 keep working: `POST {Dashboard: {value:
     * [...widgets]}}`. Top-level shape stays a bare array; per-widget
     * fix-ups apply on write so the saved shape is canonical.
     */
    public function updateSettings()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('POST only.'));
        }
        if (!isset($this->request->data['Dashboard']['value'])) {
            throw new BadRequestException(__('No setting data found.'));
        }
        $widgets = $this->request->data['Dashboard']['value'];
        if (is_string($widgets)) {
            $decoded = json_decode($widgets, true);
            $widgets = is_array($decoded) ? $decoded : array();
        }
        App::uses('LayoutFixup', 'Lib/Dashboard/Tools');
        $widgets = LayoutFixup::applyReadFixups($widgets);

        // UserSetting's validate_json hook expects the value as a JSON
        // string (matches v1's wire form: Dashboard[value]=<encoded>);
        // passing a nested array trips a json_validate type check on
        // PHP 8.3. Encode here so the model's beforeSave passes it
        // through unmodified.
        $data = array(
            'UserSetting' => array(
                'setting' => 'dashboard',
                'value'   => json_encode($widgets, JSON_UNESCAPED_SLASHES),
            ),
        );
        $result = $this->User->UserSetting->setSetting(
            $this->Auth->user(),
            $data
        );
        if ($result) {
            return $this->RestResponse->saveSuccessResponse(
                'Dashboard',
                'updateSettings',
                false,
                false,
                __('Settings updated.')
            );
        }
        return $this->RestResponse->saveFailResponse(
            'Dashboard',
            'updateSettings',
            false,
            $this->User->UserSetting->validationErrors,
            $this->response->type()
        );
    }

    public function renderWidget($instance_id = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('POST only.'));
        }
        $widgetName = isset($this->request->data['widget']) ? $this->request->data['widget'] : null;
        $rawConfig  = isset($this->request->data['config']) ? $this->request->data['config'] : '[]';
        $config = is_string($rawConfig)
            ? (json_decode($rawConfig, true) ?: array())
            : (array)$rawConfig;
        if (empty($widgetName) || !preg_match('/^[A-Za-z0-9_]+Widget$/', $widgetName)) {
            throw new BadRequestException(__('Missing or malformed widget name.'));
        }

        $widget = $this->Dashboard->loadWidget($this->Auth->user(), $widgetName);
        $data = $widget->handler($this->Auth->user(), $config);
        $renderer = method_exists($widget, 'getRenderer')
            ? $widget->getRenderer($config)
            : $widget->render;

        // Mirrors the v1 dashboards renderWidget pattern: explicit
        // exportjson / exportcsv named params force REST output even
        // from a browser session; otherwise _isRest() drives the choice.
        $named = isset($this->request->params['named']) ? $this->request->params['named'] : array();
        if (!empty($named['exportjson']) || ($this->_isRest() && empty($named['exportcsv']))) {
            return $this->RestResponse->viewData(array(
                'instance_id' => $instance_id,
                'widget'      => $widgetName,
                'config'      => $config,
                'renderer'    => $renderer,
                'data'        => $data,
            ), $this->response->type());
        }
        if (!empty($named['exportcsv'])) {
            return $this->RestResponse->viewData(
                $this->_dataToCsv($data),
                'text/csv',
                false,
                true
            );
        }

        // Web UI: render the widget body HTML via the renderer dispatcher.
        $this->layout = false;
        $this->set('widget', $widget);
        $this->set('data', $data);
        $this->set('instance_id', $instance_id);
        $this->set('renderer', $renderer);
        $this->set('config', $config);
        $this->render('render_widget');
    }

    /**
     * Flatten a widget's `handler()` return into a CSV string.
     * Mirrors the v1 dashboards renderWidget exportcsv branch closely
     * enough that REST clients written against v1 keep working.
     */
    private function _dataToCsv($data)
    {
        $toConvert = !empty($data) ? (!empty($data['data']) ? $data['data'] : $data) : array();
        if (empty($toConvert)) {
            return '';
        }
        $firstKey = key($toConvert);
        if (is_string($firstKey)) {
            $rows = array();
            foreach ($toConvert as $k => $v) {
                $rows[] = sprintf('%s,%s', $k, json_encode($v));
            }
            return implode(PHP_EOL, $rows) . PHP_EOL;
        }
        $headerKeys = array_keys(Hash::flatten($toConvert[0]));
        $header = implode(',', array_map(function ($s) { return sprintf('"%s"', $s); }, array_map('strval', $headerKeys)));
        $rows = array_map(function ($row) {
            $flat = array_values(Hash::flatten($row));
            $strs = array_map('strval', $flat);
            return implode(',', array_map(function ($s) { return sprintf('"%s"', $s); }, $strs));
        }, $toConvert);
        return $header . PHP_EOL . implode(PHP_EOL, array_values($rows)) . PHP_EOL;
    }

    /* ============================================================
     * Phase 1 v1 carryover (per audit Done note in
     * dashboard-progress.md). The five template / import / export
     * actions live here verbatim during Phase 1 so the dashboard
     * header's "⋯ More" dropdown (DD-08) keeps its URLs working.
     * Phase 4 reimplements each v2-native; until then, no edits
     * other than what the rename pass mechanically rewrites.
     * ============================================================ */

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
        $conditions = [];
        $accessible_widgets = array_keys($this->Dashboard->loadAllWidgets($this->Auth->user()));

        if (!$this->_isSiteAdmin()) {
            $permission_flags = [];
            foreach ($this->Auth->user('Role') as $perm => $value) {
                if (strpos($perm, 'perm_') !== false && !empty($value)) {
                    $permission_flags[] = $perm;
                }
            }
            $conditions['AND'] = [
                [
                    'OR' => [
                        'Dashboard.user_id' => $this->Auth->user('id'),
                        'AND' => [
                            'Dashboard.selectable' => 1,
                            ['OR' => [
                                ['Dashboard.restrict_to_org_id' => $this->Auth->user('org_id')],
                                ['Dashboard.restrict_to_org_id' => 0]
                            ]],
                            ['OR' => [
                                ['Dashboard.restrict_to_role_id' => $this->Auth->user('role_id')],
                                ['Dashboard.restrict_to_role_id' => 0]
                            ]],
                            ['OR' => [
                                ['Dashboard.restrict_to_permission_flag' => $permission_flags],
                                ['Dashboard.restrict_to_permission_flag' => 0]
                            ]]
                        ]
                    ]
                ]
            ];
        }

        $currentUserId = $this->Auth->user('id');
        $params = [
            'filters' => ['name', 'description', 'uuid', 'value'],
            'quickFilters' => ['name', 'description', 'uuid'],
            'quickFilterParameter' => 'value',
            'conditions' => $conditions,
            'contain' => ['User.id', 'User.email'],
            'afterFind' => function ($data) use ($accessible_widgets, $currentUserId) {
                foreach ($data as &$element) {
                    $element['Dashboard']['value'] = json_decode($element['Dashboard']['value'], true);
                    if (!$this->_isRest()) {
                        $widgets = [];
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
                        if ($element['Dashboard']['user_id'] != $currentUserId) {
                            $element['User']['email'] = '';
                        }
                    }
                }
                return $data;
            }
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('passedArgs', json_encode($this->passedArgs));
        $this->set('data', $this->viewVars['data']);
    }

    public function deleteTemplate($id)
    {
        $conditions = [];
        if (Validation::uuid($id)) {
            $conditions['Dashboard.uuid'] = $id;
        }
        if (!$this->_isSiteAdmin()) {
            $conditions['Dashboard.user_id'] = $this->Auth->user('id');
        }
        $params = [
            'conditions' => $conditions,
            'redirect' => $this->baseurl . '/dashboards/listTemplates'
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
