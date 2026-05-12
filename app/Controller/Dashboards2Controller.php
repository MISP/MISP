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
    public $uses = array('Dashboard');

    public function beforeFilter()
    {
        parent::beforeFilter();
        // POST /renderWidget carries widget config in its body — same
        // CSRF posture as the v1 dashboard renderer.
        $this->Security->unlockedActions[] = 'renderWidget';
        if ($this->request->action === 'renderWidget') {
            $this->Security->doNotGenerateToken = true;
        }
    }

    public function index()
    {
        // Hardcoded prototype layout — three real MISP widgets.
        // Real persistence (UserSetting:dashboard read with on-read
        // fix-ups) lands in the last Phase 0.3 task.
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

        // REST clients get the layout payload as JSON via the
        // RestResponse component (matches the v1 dashboards export()
        // pattern). Web UI falls through to View/Dashboards2/index.ctp.
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($widgets, $this->response->type());
        }

        $this->layout = false;
        $this->set('widgets', $widgets);
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
