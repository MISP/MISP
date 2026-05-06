<?php
App::uses('AppController', 'Controller');

/**
 * Phase 0.3 prototype controller for dashboard v2.
 *
 * Throwaway. Mounted at /dashboards/proto via a route in
 * app/Config/routes.php. Once Phase 0 sign-off lands and Phase 1
 * starts the in-place replacement of v1, this controller is removed
 * and the prototype's surviving code (renderers, JS, CSS) moves
 * onto the canonical /dashboards/* routes.
 *
 * Keeps the v1 DashboardsController completely untouched.
 *
 * @property Dashboard $Dashboard
 */
class DashboardsProtoController extends AppController
{
    public $components = ['Session', 'RequestHandler'];
    public $uses = ['Dashboard'];

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
        $widgets = [
            [
                'instance_id' => 'w_1',
                'widget'      => 'MispStatusWidget',
                'alias'       => null,
                'config'      => [],
                'position'    => ['x' => 0, 'y' => 0, 'w' => 4, 'h' => 3],
            ],
            [
                'instance_id' => 'w_2',
                'widget'      => 'TrendingTagsWidget',
                'alias'       => null,
                'config'      => ['time_window' => 'P7D', 'threshold' => 10],
                'position'    => ['x' => 4, 'y' => 0, 'w' => 5, 'h' => 4],
            ],
            [
                'instance_id' => 'w_3',
                'widget'      => 'OrganisationMapWidget',
                'alias'       => null,
                'config'      => [],
                'position'    => ['x' => 9, 'y' => 0, 'w' => 3, 'h' => 4],
            ],
        ];
        $this->set('widgets', $widgets);
    }

    public function renderWidget($instance_id = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('POST only.'));
        }
        $widgetName = $this->request->data['widget'] ?? null;
        $rawConfig  = $this->request->data['config'] ?? '[]';
        $config = is_string($rawConfig) ? (json_decode($rawConfig, true) ?: []) : (array)$rawConfig;
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
