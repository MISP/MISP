<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_notify_user_toast extends WorkflowBaseActionModule
{
    public $id = 'notify-user-toast';
    public $name = 'Notify User Toast';
    public $description = 'Allow to send a toast in the UI to the user that initiated the workflow.';
    public $icon = 'bell';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = false;
    public $params = [];

    protected $User;

    private $variants = ['danger', 'warning', 'info', ];
    public function __construct()
    {
        parent::__construct();

        $this->User = ClassRegistry::init('User');
        $this->params = [
            [
                'id' => 'variant',
                'label' => 'Variant',
                'type' => 'select',
                'options' => array_combine($this->variants, $this->variants),
                'default' => 'info',
            ],
            [
                'id' => 'toast_header',
                'label' => 'Toast Header',
                'type' => 'textarea',
                'placeholder' => __('The **template** will be rendered using *Jinja2*!'),
                'jinja_supported' => true,
            ],
            [
                'id' => 'toast_body',
                'label' => 'Toast Body',
                'type' => 'textarea',
                'placeholder' => __('The **template** will be rendered using *Jinja2*!'),
                'jinja_supported' => true,
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $initiatorUser = $roamingData->getInitiatorUser();
        $params = $this->getParamsWithValues($node, $rData);
        $workflowTriggerName = !empty($roamingData->getTriggerNode) ? $roamingData->getTriggerNode() : $this->id;
        if (empty($params['toast_header']['value']) && empty($params['toast_body']['value'])) {
            $errors[] = __('The toast text is empty.');
            return false;
        }

        $renderedHeader = "[{$workflowTriggerName}] " . $params['toast_header']['value'];
        $renderedBody = $params['toast_body']['value'];
        $variant = $params['variant']['value'];

        return $this->notifyWithToast($initiatorUser, $renderedHeader, $renderedBody, $variant);
    }

    protected function notifyWithToast(array $user, $header, $body, $variant): bool
    {
        return $this->User->createNotificationToast($user, $header, $body, $variant);
    }
}
