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

    /** @var PubSubTool */
    private static $loadedPubSubTool;


    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'input',
                'label' => 'ZMQ Topic',
                'default' => 'from-misp-workflow',
            ],
            [
                'type' => 'input',
                'label' => 'Content',
                'default' => '',
                'placeholder' => 'Whatever text to be published'
            ],
        ];
    }

    public function exec(array $node)
    {
        $params = $this->getParams($node);
        $this->pushZmqHandler([
            'Node content' => $params['Content']['value']
        ]);
    }

    public function pushZmqHandler($message)
    {
        if (!self::$loadedPubSubTool) {
            App::uses('PubSubTool', 'Tools');
            $pubSubTool = new PubSubTool();
            $pubSubTool->initTool();
            self::$loadedPubSubTool = $pubSubTool;
        }
        $pubSubTool = self::$loadedPubSubTool;
        $pubSubTool->workflow_push($message);
    }
}
