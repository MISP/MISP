<?php
use Cake\ORM\TableRegistry;

require_once(ROOT . DS . 'libraries' . DS . 'default' . DS . 'OutboxProcessors' . DS . 'GenericOutboxProcessor.php'); 

class BroodsOutboxProcessor extends GenericOutboxProcessor
{
    protected $scope = 'Broods';
    protected $action = 'not-specified'; //overriden when extending
    protected $description = ''; // overriden when extending
    protected $registeredActions = [
        'ResendFailedMessage',
    ];

    public function __construct($loadFromAction=false) {
        parent::__construct($loadFromAction);
    }

    public function create($requestData)
    {
        return parent::create($requestData);
    }

    protected function getIssuerBrood($broodId)
    {
        $brood = $this->Broods->find()
            ->where(['id' => $broodId])
            ->first();
        return $brood;
    }

    protected function getLocalTool($toolId)
    {
        $tool = $this->LocalTools->find()
            ->where(['id' => $toolId])
            ->first();
        return $tool;
    }

    protected function getConnector($className)
    {
        try {
            $connectorClasses = $this->LocalTools->getConnectors($className);
            if (!empty($connectorClasses)) {
                $connector = array_values($connectorClasses)[0];
            }
        } catch (NotFoundException $e) {
            $connector = null;
        }
        return $connector;
    }

    protected function setRemoteToolConnectionStatus(Object $brood, Object $outboxRequest, String $status): void
    {
        $connector = $this->getConnector($outboxRequest->data['remote_tool']['connector']);
        $connection = $this->getLocalTool($outboxRequest->data['local_tool_id']);
        $connectorParams = [
            'connection' => $connection,
            'remote_tool' => $outboxRequest->data['remote_tool'],
            'remote_cerebrate' => $brood,
        ];
        $connector->remoteToolConnectionStatus($connectorParams, constant(get_class($connector) . '::' . $status));
    }
}

class ResendFailedMessageProcessor extends BroodsOutboxProcessor implements GenericOutboxProcessorActionI {
    public $action = 'ResendFailedMessage';
    protected $description;

    public function __construct() {
        parent::__construct();
        $this->description = __('Handle re-sending messages that failed to be received from other cerebrate instances.');
        $this->Broods = TableRegistry::getTableLocator()->get('Broods');
        $this->LocalTools = \Cake\ORM\TableRegistry::getTableLocator()->get('LocalTools');
    }

    protected function addValidatorRules($validator)
    {
        return $validator;
    }

    public function getViewVariables($request)
    {
        $request->brood = $this->getIssuerBrood($request['data']['brood_id']);
        $request->individual = $request->user->individual;
        $request->localTool = $this->getLocalTool($request['data']['local_tool_id']);
        $request->remoteTool = $request['data']['remote_tool'];
        return [
            'request' => $request,
        ];
    }
    
    public function create($requestData) {
        $this->validateRequestData($requestData);
        $brood = $requestData['brood'];
        $requestData['title'] = __('Issue while sending message to Cerebrate instance `{0}` using `{1}`', $brood->name, sprintf('%s.%s', $requestData['model'], $requestData['action']));
        return parent::create($requestData);
    }

    public function process($id, $requestData, $outboxRequest)
    {
        $brood = $this->getIssuerBrood((int) $outboxRequest->data['brood_id']);
        if (!empty($requestData['is_delete'])) { // -> declined
            $success = true;
            $messageSucess = __('Message successfully deleted');
            $messageFail = '';
            $this->setRemoteToolConnectionStatus($brood, $outboxRequest, 'STATE_CANCELLED');
        } else {
            $url = $outboxRequest->data['url'];
            $dataSent = $outboxRequest->data['sent'];
            $response = $this->Broods->sendRequest($brood, $url, true, $dataSent);
            $jsonReply = $response->getJson();
            if (is_null($jsonReply)) {
                $jsonReply = [
                    'success' => false,
                    'errors' => [
                        __('Brood returned an invalid JSON.')
                    ]
                ];
            }
            $success = !empty($jsonReply['success']);
            $messageSuccess = __('Message successfully sent to `{0}`', $brood->name);
            $messageFail = __('Could not send message to `{0}`.', $brood->name);
            if ($success) {
                $this->setRemoteToolConnectionStatus($brood, $outboxRequest, $outboxRequest->data['next_connector_state']);
            } else {
                $this->setRemoteToolConnectionStatus($brood, $outboxRequest, 'STATE_SENDING_ERROR');
            }
        }
        if ($success) {
            $this->discard($id, $requestData);
        }
        return $this->genActionResult(
            [],
            $success,
            $success ? $messageSuccess : $messageFail,
            $jsonReply['errors'] ?? []
        );
    }

    public function discard($id, $requestData)
    {
        return parent::discard($id, $requestData);
    }
}
