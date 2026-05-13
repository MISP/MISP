<?php
App::uses('AppController', 'Controller');

/**
 * Phase 0.3+ controller for dashboard v2.
 *
 * Mounted at /dashboards2/* via CakePHP's default routing. The "2"
 * suffix is intentionally cheap — it'll get renamed to /dashboards/
 * (and this file moved to DashboardsController) at the end of the
 * development cycle when v1 is removed (Q5: straight in-place
 * replacement on the `dashboards` branch).
 *
 * Keeps the v1 DashboardsController completely untouched.
 *
 * @property Dashboard $Dashboard
 */
class Dashboards2Controller extends AppController
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
        // Persistence path (Phase 0.3 demo of DD-05 on-read fix-ups):
        //   1. read UserSetting:dashboard for the current user,
        //   2. apply per-widget read fix-ups (width/height → w/h,
        //      instance_id mint) so legacy v1 rows render correctly,
        //   3. fall back to the hardcoded proto layout if no row exists
        //      so a first-time viewer sees the demo state.
        // updateSettings writes go through the same fix-up so persisted
        // shape is canonical. Top-level stays bare-array (DD-05).
        $saved = $this->User->UserSetting->getSetting(
            $this->Auth->user('id'),
            'dashboard'
        );
        if (!empty($saved) && is_array($saved)) {
            $widgets = LayoutFixup::applyReadFixups($saved);
        } else {
            $widgets = $this->_defaultProtoLayout();
        }

        // REST clients get the layout payload as JSON via the
        // RestResponse component (matches the v1 dashboards export()
        // pattern). Web UI falls through to View/Dashboards2/index.ctp.
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($widgets, $this->response->type());
        }

        $this->layout = false;
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

    private function _defaultProtoLayout()
    {
        $widgets = array(
            array(
                'instance_id' => 'w_1',
                'widget'      => 'MispStatusWidget',
                'alias'       => null,
                'config'      => array(),
                'position'    => array('x' => 0, 'y' => 0, 'w' => 4, 'h' => 3),
            ),
            array(
                'instance_id' => 'w_2',
                'widget'      => 'TrendingTagsWidget',
                'alias'       => null,
                // NB: legacy widget parser expects "7d" (lowercase),
                // not the ISO-8601 `P7D` the canonical-type catalogue
                // uses — the canonical → legacy adapter is a Phase 2
                // task. See progress tracker "Discovered work".
                // `-1` is the widget's "all time" sentinel so the
                // prototype renders bars regardless of how recent
                // event activity is on this instance.
                'config'      => array('time_window' => '-1', 'threshold' => 10),
                'position'    => array('x' => 4, 'y' => 0, 'w' => 5, 'h' => 4),
            ),
            array(
                'instance_id' => 'w_3',
                'widget'      => 'OrganisationMapWidget',
                'alias'       => null,
                'config'      => array(),
                'position'    => array('x' => 9, 'y' => 0, 'w' => 3, 'h' => 4),
            ),
            // Second `time_window` declarer so the toolbar's bulk-edit
            // path (DD-05) has more than one widget to sync — seeded
            // with a different window from TrendingTags so the chip
            // shows "(mixed)" on first load and the bulk-pull is
            // immediately observable. Uses the existing BarChart shim.
            array(
                'instance_id' => 'w_4',
                'widget'      => 'OrgContributionToplistWidget',
                'alias'       => null,
                'config'      => array('time_window' => '30d', 'threshold' => 10),
                'position'    => array('x' => 0, 'y' => 4, 'w' => 12, 'h' => 4),
            ),
        );
        return $widgets;
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
}
