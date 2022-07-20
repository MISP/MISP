<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_push_zmq extends WorkflowBaseActionModule
{
    public $blocking = false;
    public $id = 'push-zmq';
    public $name = 'Push to ZMQ';
    public $description = 'Push to the ZMQ channel';
    public $icon_path = 'zeromq.png';
    public $inputs = 1;
    public $outputs = 1;
    public $params = [];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'input',
                'label' => 'Namespace',
                'default' => '',
                'placeholder' => __('A namespace in the ZMQ topic')
            ],
            [
                'type' => 'input',
                'label' => 'Content',
                'default' => '',
                'placeholder' => __('Whatever text to be published')
            ],
            [
                'type' => 'input',
                'label' => 'Match Condition',
                'default' => '',
                'placeholder' => 'Attribute.{n}.AttributeTag.{n}.Tag.name',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);
        $path = $params['Match Condition']['value'];
        $data = $roamingData->getData();
        $extracted = $this->extractData($data, $path);
        if ($extracted === false) {
            $errors[] = __('Error while trying to extract data with path `%s`', $path);
            return false;
        }
        $this->push_zmq([
            'namespace' => $params['Namespace']['value'],
            'content' => $params['Content']['value'],
            'extracted' => JsonTool::encode($extracted),
        ]);
        return true;
    }
}
