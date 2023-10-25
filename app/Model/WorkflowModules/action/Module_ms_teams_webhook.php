<?php
include_once APP . 'Model/WorkflowModules/action/Module_webhook.php';

class Module_ms_teams_webhook extends Module_webhook
{
    public $id = 'ms-teams-webhook';
    public $name = 'MS Teams Webhook';
    public $version = '0.5';
    public $description = 'Perform callbacks to the MS Teams webhook provided by the "Incoming Webhook" connector';
    public $icon_path = 'MS_Teams.png';

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'url',
                'label' => 'MS Teams Webhook URL',
                'type' => 'input',
                'placeholder' => 'https://example.com/test',
            ],
            [
                'id' => 'content_type',
                'label' => 'Content type',
                'type' => 'select',
                'default' => 'form',
                'options' => [
                    'form' => 'application/x-www-form-urlencoded',
                ],
            ],
            [
                'id' => 'data_extraction_path',
                'label' => 'Data extraction path',
                'type' => 'hashpath',
                'default' => '',
                'placeholder' => 'Attribute.{n}.AttributeTag.{n}.Tag.name',
            ],
        ];
    }

    protected function doRequest($url, $contentType, $data, $headers = [], $requestMethod='post', $serverConfig = null)
    {
        $data = ['text' => JsonTool::encode($data)];
        return parent::doRequest($url, $contentType, $data);
    }
}
