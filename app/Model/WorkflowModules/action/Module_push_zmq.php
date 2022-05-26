<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_push_zmq extends WorkflowBaseModule
{
    public $id = 'push-zmq';
    public $name = 'Push to ZMQ';
    public $description = 'Push to the ZMQ channel';
    public $icon = 'wifi';
    public $icon_class = 'fas fa-rotate-90';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'input',
                'label' => 'Namespace',
                'default' => '',
                'placeholder' => 'A namespace in the ZMQ topic'
            ],
            [
                'type' => 'input',
                'label' => 'Content',
                'default' => '',
                'placeholder' => 'Whatever text to be published'
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData): bool
    {
        parent::exec($node, $roamingData);
        $params = $this->getParamsWithValues($node);
        // $this->push_zmq([
        //     'Module_push_zmq has passed option' => $params['Content']['value']
        // ]);
        debug($params);
        $this->push_zmq([
            'content' => $params['Content']['value'],
            'pass_along' => $roamingData->getData(),
        ], $params['Namespace']['value']);
        return true;
    }
}
