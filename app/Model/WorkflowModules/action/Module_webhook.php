<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Module_webhook extends WorkflowBaseActionModule
{
    public $id = 'webhook';
    public $name = 'Webhook';
    public $description = 'Allow to perform custom callbacks to the provided URL';
    public $icon_path = 'webhook.png';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = false;
    public $params = [];

    private $timeout = false;
    private $Event;

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'input',
                'label' => 'Payload URL',
                'placeholder' => 'https://example.com/test',
            ],
            [
                'type' => 'select',
                'label' => 'Content type',
                'default' => 'form',
                'options' => [
                    'json' => 'application/json',
                    'form' => 'application/x-www-form-urlencoded',
                ],
            ],
            [
                'type' => 'input',
                'label' => 'Data extraction path',
                'default' => '',
                'placeholder' => 'Attribute.{n}.AttributeTag.{n}.Tag.name',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);
        if (empty($params['Payload URL']['value'])) {
            $errors[] = __('URL not provided.');
            return false;
        }

        $rData = $roamingData->getData();
        $path = $params['Data extraction path']['value'];
        $extracted = !empty($params['Data extraction path']['value']) ? $this->extractData($rData, $path) : $rData;
        try {
            $response = $this->doRequest($params['Payload URL']['value'], $params['Content type']['value'], $extracted);
            if ($response->isOk()) {
                return true;
            }
            if ($response->code === 403 || $response->code === 401) {
                $errors[] = __('Authentication failed.');
                return false;
            }
            $errors[] = __('Something went wrong with the request or the remote side is having issues. Body returned: %s', $response->body);
            return false;
        } catch (SocketException $e) {
            $errors[] = __('Something went wrong while sending the request. Error returned: %s', $e->getMessage());
            return false;
        } catch (Exception $e) {
            $errors[] = __('Something went wrong. Error returned: %s', $e->getMessage());
            return false;
        }
        $errors[] = __('Something went wrong with the request or the remote side is having issues.');
        return false;
    }

    private function doRequest($url, $contentType, array $data)
    {
        $this->Event = ClassRegistry::init('Event'); // We just need a model to use AppModel functions
        $version = implode('.', $this->Event->checkMISPVersion());
        $commit = $this->Event->checkMIPSCommit();

        $request = [
            'header' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'MISP ' . $version . (empty($commit) ? '' : ' - #' . $commit),
            ]
        ];
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocket(null, $this->timeout);
        if ($contentType == 'form') {
            $request['header']['Content-Type'] = 'application/x-www-form-urlencoded';
            $response = $HttpSocket->post($url, $data, $request);
        } else {
            $response = $HttpSocket->post($url, JsonTool::encode($data), $request);
        }
        return $response;
    }
}
