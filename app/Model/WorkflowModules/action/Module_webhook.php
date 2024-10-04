<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Module_webhook extends WorkflowBaseActionModule
{
    public $id = 'webhook';
    public $name = 'Webhook';
    public $version = '0.7';
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
                'id' => 'url',
                'label' => __('URL'),
                'type' => 'input',
                'placeholder' => 'https://example.com/test',
                'jinja_supported' => true,
            ],
            [
                'id' => 'content_type',
                'label' => __('Content type'),
                'type' => 'select',
                'default' => 'json',
                'options' => [
                    'json' => 'application/json',
                    'form' => 'application/x-www-form-urlencoded',
                ],
            ],
            [
                'id' => 'request_method',
                'label' => __('HTTP Request Method'),
                'type' => 'select',
                'default' => 'post',
                'options' => [
                    'post' => 'POST',
                    'get' => 'GET',
                    'put' => 'PUT',
                    'delete' => 'DELETE',
                ],
            ],
            [
                'id' => 'self_signed',
                'label' => __('Self-signed certificates'),
                'type' => 'select',
                'default' => 'deny',
                'options' => [
                    'deny' => 'Deny self-signed certificates',
                    'allow' => 'Allow self-signed certificates',
                ],
            ],
            [
                'id' => 'payload',
                'label' => __('Payload (leave empty for roaming data)'),
                'type' => 'textarea',
                'default' => '',
                'placeholder' => '',
                'jinja_supported' => true,
            ],
            [
                'id' => 'headers',
                'label' => __('Headers'),
                'type' => 'textarea',
                'placeholder' => 'Authorization: foobar',
                'jinja_supported' => true,
            ],
        ];
    }

    public function diagnostic(): array
    {
        $errors = array_merge(parent::diagnostic(), []);
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors = $this->addNotification(
                $errors,
                'error',
                __('`rest_client_enable_arbitrary_urls` is turned off.'),
                __('The module will not send any request as long as `Security.rest_client_enable_arbitrary_urls` is turned off.'),
                [
                    __('This is a security measure to ensure a site-admin do not send arbitrary request to internal services')
                ],
                true,
                true
            );
        }
        return $errors;
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors[] = __('`Security.rest_client_enable_arbitrary_urls` is turned off');
            return false;
        }
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['url']['value'])) {
            $errors[] = __('URL not provided.');
            return false;
        }

        $payload = '';
        if (strlen($params['payload']['value']) > 0) {
            $payload = $params['payload']['value'];
        } else {
            $payload = $rData;
        }
        if ($params['content_type']['value'] == 'json') {
            try {
                if (is_string($payload)) {
                    $payload = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
                }
            } catch (Exception $e) {
                // Do nothing. simply send the payload as is
            }
        }
        $tmpHeaders = explode(PHP_EOL, $params['headers']['value']);
        $headers = [];
        $selfSignedAllowed = $params['self_signed']['value'] == 'allow';
        foreach ($tmpHeaders as $entry) {
            $entry = explode(':', $entry, 2);
            if (count($entry) == 2) {
                $headers[trim($entry[0])] = trim($entry[1]);
            }
        }
        try {
            $response = $this->doRequest($params['url']['value'], $params['content_type']['value'], $payload, $headers, $params['request_method']['value'], ['self_signed' => $selfSignedAllowed]);
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

    protected function doRequest($url, $contentType, $data, $headers = [], $requestMethod='post', $serverConfig = null)
    {
        $this->Event = ClassRegistry::init('Event'); // We just need a model to use AppModel functions
        $version = implode('.', $this->Event->checkMISPVersion());
        $commit = $this->Event->checkMIPSCommit();

        $request = [
            'header' => array_merge([
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'MISP ' . $version . (empty($commit) ? '' : ' - #' . $commit),
            ], $headers)
        ];
        $syncTool = new SyncTool();
        $serverConfig = !empty($serverConfig['Server']) ? $serverConfig : ['Server' => $serverConfig];
        $HttpSocket = $syncTool->setupHttpSocket($serverConfig, $this->timeout);
        $encodedData = $data;
        if ($contentType == 'form') {
            $request['header']['Content-Type'] = 'application/x-www-form-urlencoded';
        } else {
            $encodedData = JsonTool::encode($data);
        }
        switch ($requestMethod) {
            case 'post':
                $response = $HttpSocket->post($url, $encodedData, $request);
                break;
            case 'get':
                $response = $HttpSocket->get($url, false, $request);
                break;
            case 'put':
                $response = $HttpSocket->put($url, $encodedData, $request);
                break;
            case 'delete':
                $response = $HttpSocket->delete($url, $encodedData, $request);
                break;
        }
        return $response;
    }
}
