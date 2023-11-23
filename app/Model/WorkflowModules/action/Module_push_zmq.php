<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_push_zmq extends WorkflowBaseActionModule
{
    public $blocking = false;
    public $id = 'push-zmq';
    public $name = 'Push to ZMQ';
    public $version = '0.2';
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
                'id' => 'data_extraction_path',
                'label' => 'Data extraction path',
                'type' => 'hashpath',
                'default' => '',
                'placeholder' => 'Attribute.{n}.AttributeTag.{n}.Tag.name',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $path = $params['data_extraction_path']['value'];
        $extracted = $this->extractData($rData, $path);
        if ($extracted === false) {
            $errors[] = __('Error while trying to extract data with path `%s`', $path);
            return false;
        }
        $this->push_zmq($extracted);
        return true;
    }
}
