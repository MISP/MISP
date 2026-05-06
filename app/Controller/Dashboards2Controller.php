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
        $this->layout = false;

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
                'config'      => array('time_window' => 'P7D', 'threshold' => 10),
                'position'    => array('x' => 4, 'y' => 0, 'w' => 5, 'h' => 4),
            ),
            array(
                'instance_id' => 'w_3',
                'widget'      => 'OrganisationMapWidget',
                'alias'       => null,
                'config'      => array(),
                'position'    => array('x' => 9, 'y' => 0, 'w' => 3, 'h' => 4),
            ),
        );
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

        $this->layout = false;
        $this->set('widget', $widget);
        $this->set('data', $data);
        $this->set('instance_id', $instance_id);
        $this->set('renderer', method_exists($widget, 'getRenderer')
            ? $widget->getRenderer($config)
            : $widget->render);
        $this->set('config', $config);
        $this->render('render_widget');
    }
}
