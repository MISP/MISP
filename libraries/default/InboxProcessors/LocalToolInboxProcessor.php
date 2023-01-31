<?php
use Cake\ORM\TableRegistry;
use Cake\Filesystem\File;
use Cake\Http\Exception\NotFoundException;

require_once(ROOT . DS . 'libraries' . DS . 'default' . DS . 'InboxProcessors' . DS . 'GenericInboxProcessor.php'); 

class LocalToolInboxProcessor extends GenericInboxProcessor
{
    protected $scope = 'LocalTool';
    protected $action = 'not-specified'; //overriden when extending
    protected $description = ''; // overriden when extending
    protected $registeredActions = [
        'IncomingConnectionRequest',
        'AcceptedRequest',
        'DeclinedRequest',
    ];
    protected $processingTemplate = 'LocalTool/GenericRequest';
    protected $Broods;
    protected $LocalTools;

    public function __construct($loadFromAction=false)
    {
        parent::__construct($loadFromAction);
        $this->Broods = TableRegistry::getTableLocator()->get('Broods');
        $this->LocalTools = TableRegistry::getTableLocator()->get('LocalTools');
    }

    public function create($requestData)
    {
        return parent::create($requestData);
    }

    protected function updateProcessingTemplate($request)
    {
        $connectorName = $request->connector['connector'];
        $processingTemplatePath = sprintf('%s/%s/%s.php', $this->scope, $connectorName, $this->action);
        $file = new File($this->processingTemplatesDirectory . DS . $processingTemplatePath);
        if ($file->exists()) {
            $this->processingTemplate = str_replace('.php', '', $processingTemplatePath);
        }
        $file->close();
    }

    protected function validateConnectorName($requestData)
    {
        if (empty($requestData['data']['connectorName'])) {
            throw new NotFoundException('Error while validating request data. Connector name is missing.');
        }
        $connector = $this->getConnectorFromClassname($requestData['data']['connectorName']);
        if (is_null($connector)) {
            throw new NotFoundException(__('Error while validating request data. Unkown connector `{0}`', $requestData['data']['connectorName']));
        }
    }

    protected function getIssuerBrood($request)
    {
        $brood = $this->Broods->find()
            ->where(['url' => $request['origin']])
            ->first();
        return $brood;
    }

    protected function getConnection($requestData)
    {
        $local_tool_id = $requestData['remote_tool_id']; // local_tool_id is actually the remote_tool_id for the sender
        $connection = $this->LocalTools->find()->where(['id' => $local_tool_id])->first();
        return $connection;
    }

    protected function filterAlignmentsForBrood($individual, $brood)
    {
        foreach ($individual->alignments as $i => $alignment) {
            if ($alignment->organisation_id != $brood->organisation_id) {
                unset($individual->alignments[$i]);
            }
        }
        return $individual;
    }

    protected function getConnector($request)
    {
        try {
            $connectorClasses = $this->LocalTools->getConnectors($request->local_tool_connector_name);
            if (!empty($connectorClasses)) {
                $connector = array_values($connectorClasses)[0];
            }
        } catch (NotFoundException $e) {
            $connector = null;
        }
        return $connector;
    }

    protected function getConnectorMeta($request)
    {
        try {
            $className = $request->local_tool_connector_name;
            $connector = $this->getConnectorFromClassname($className);
            $connectorMeta = $this->LocalTools->extractMeta([$className => $connector])[0];
        } catch (NotFoundException $e) {
            $connectorMeta = [];
        }
        return $connectorMeta;
    }

    protected function getConnectorFromClassname($className)
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

    protected function getConnectorMetaFromClassname($className)
    {
        try {
            $connector = $this->getConnectorFromClassname($className);
            $connectorMeta = $this->LocalTools->extractMeta([$className => $connector])[0];
        } catch (NotFoundException $e) {
            $connectorMeta = [];
        }
        return $connectorMeta;
    }

    protected function attachRequestAssociatedData($request)
    {
        $request->brood = $this->getIssuerBrood($request);
        $request->connector = $this->getConnectorMeta($request);
        $request->individual = $request->user->individual;
        $request->individual = $this->filterAlignmentsForBrood($request->individual, $request->brood);
        return $request;
    }

    protected function genBroodParam($remoteCerebrate, $connection, $connector, $requestData)
    {
        $local_tool_id = $requestData['remote_tool_id']; // local_tool_id is actually the remote_tool_id for the sender
        $remote_tool_id = $requestData['local_tool_id']; // remote_tool_id is actually the local_tool_id for the sender
        $remote_org = $this->Broods->Organisations->find()->where(['id' => $remoteCerebrate->organisation_id])->first();
        return [
            'remote_tool' => [
                'id' => $remote_tool_id,
                'connector' => $connector->connectorName,
                'name' => $requestData['tool_name'],
            ],
            'remote_org' => $remote_org,
            'remote_tool_data' => $requestData,
            'remote_cerebrate' => $remoteCerebrate,
            'connection' => $connection,
            'connector' => [$connector->connectorName => $connector],
        ];
    }

    protected function addBaseValidatorRules($validator)
    {
        return $validator
            ->requirePresence('connectorName')
            ->notEmptyString('connectorName', 'The connector name must be provided')
            ->requirePresence('cerebrateURL')
            ->notEmptyString('cerebrateURL', 'A url must be provided')
            ->requirePresence('local_tool_id')
            ->numeric('local_tool_id', 'A local_tool_id must be provided')
            ->requirePresence('remote_tool_id')
            ->numeric('remote_tool_id', 'A remote_tool_id must be provided');
            // ->add('url', 'validFormat', [
            //     'rule' => 'url',
            //     'message' => 'URL must be valid'
            // ]);
    }
}

class IncomingConnectionRequestProcessor extends LocalToolInboxProcessor implements GenericInboxProcessorActionI {
    public $action = 'IncomingConnectionRequest';
    protected $description;

    public function __construct() {
        parent::__construct();
        $this->description = __('Handle Phase I of inter-connection when another cerebrate instance performs the request.');
    }

    protected function addValidatorRules($validator)
    {
        return $this->addBaseValidatorRules($validator);
    }
    
    public function create($requestData) {
        $this->validateConnectorName($requestData);
        $this->validateRequestData($requestData);
        $connectorMeta = $this->getConnectorMetaFromClassname($requestData['data']['connectorName']);
        $requestData['title'] = __('Request for {0} Inter-connection', $connectorMeta['name']);
        return parent::create($requestData);
    }

    public function getViewVariables($request)
    {
        $request = $this->attachRequestAssociatedData($request);
        return [
            'request' => $request,
            'progressStep' => 0,
        ];
    }

    public function process($id, $requestData, $inboxRequest)
    {
        /**
         * /!\ Should how should sent message be? be fire and forget? Only for delined?
         */
        $interConnectionResult = [];
        $remoteCerebrate = $this->getIssuerBrood($inboxRequest);
        $connector = $this->getConnector($inboxRequest);
        if (!empty($requestData['is_discard'])) { // -> declined
            $connectorResult = $this->declineConnection($connector, $remoteCerebrate, $inboxRequest['data']); // Fire-and-forget?
            $connectionSuccessfull = !empty($connectorResult['success']);
            $resultTitle = __('Could not sent declined message to `{0}`\'s  for {1}', $inboxRequest['origin'], $inboxRequest['local_tool_name']);
            $errors = [];
            if ($connectionSuccessfull) {
                $resultTitle = __('Declined message successfully sent to `{0}`\'s for {1}', $inboxRequest['origin'], $inboxRequest['local_tool_name']);
                $this->discard($id, $inboxRequest);
            }
        } else {
            $errors = [];
            $connectorResult = [];
            $thrownErrorMessage = '';
            try {
                $connectorResult = $this->acceptConnection($connector, $remoteCerebrate, $inboxRequest['data']);
                $connectionSuccessfull = !empty($connectorResult['success']);
            } catch (\Throwable $th) {
                $connectionSuccessfull = false;
                $thrownErrorMessage = $th->getMessage();
            }
            $resultTitle = $connectorResult['message'] ?? __('Could not inter-connect `{0}`\'s {1}', $inboxRequest['origin'], $inboxRequest['local_tool_name']);
            $errors = $connectorResult['errors'] ?? $thrownErrorMessage;
            if ($connectionSuccessfull) {
                $resultTitle = __('Interconnection for `{0}`\'s {1} created', $inboxRequest['origin'], $inboxRequest['local_tool_name']);
            }
            if ($connectionSuccessfull || !empty($connectorResult['placed_in_outbox'])) {
                $this->discard($id, $inboxRequest);
            }
        }
        return $this->genActionResult(
            $connectorResult,
            $connectionSuccessfull,
            $resultTitle,
            $errors
        );
    }

    public function discard($id, $requestData)
    {
        return parent::discard($id, $requestData);
    }

    protected function acceptConnection($connector, $remoteCerebrate, $requestData)
    {
        $connection = $this->getConnection($requestData);
        $params = $this->genBroodParam($remoteCerebrate, $connection, $connector, $requestData);
        $connectorResult = $connector->acceptConnectionWrapper($params);
        $response = $this->sendAcceptedRequestToRemote($params, $connectorResult);
        return $response;
    }

    protected function declineConnection($connector, $remoteCerebrate, $requestData)
    {
        $connection = $this->getConnection($requestData);
        $params = $this->genBroodParam($remoteCerebrate, $connection, $connector, $requestData);
        $connectorResult = $connector->declineConnectionWrapper($params);
        $response = $this->sendDeclinedRequestToRemote($params, $connectorResult);
        return $response;
    }

    protected function sendAcceptedRequestToRemote($params, $connectorResult)
    {
        $response = $this->Broods->sendLocalToolAcceptedRequest($params, $connectorResult);
        return $response;
    }

    protected function sendDeclinedRequestToRemote($remoteCerebrate, $connectorResult)
    {
        $response = $this->Broods->sendLocalToolDeclinedRequest($params, $connectorResult);
        return $response;
    }
}

class AcceptedRequestProcessor extends LocalToolInboxProcessor implements GenericInboxProcessorActionI {
    public $action = 'AcceptedRequest';
    protected $description;

    public function __construct() {
        parent::__construct();
        $this->description = __('Handle Phase II of inter-connection when initial request has been accepted by the remote cerebrate.');
    }

    protected function addValidatorRules($validator)
    {
        return $this->addBaseValidatorRules($validator);
    }
    
    public function create($requestData) {
        $this->validateConnectorName($requestData);
        $this->validateRequestData($requestData);
        $connectorMeta = $this->getConnectorMetaFromClassname($requestData['data']['connectorName']);
        $requestData['title'] = __('Inter-connection for {0} has been accepted', $connectorMeta['name']);
        return parent::create($requestData);
    }

    public function getViewVariables($request)
    {
        $request = $this->attachRequestAssociatedData($request);
        return [
            'request' => $request,
            'progressStep' => 1,
        ];
    }

    public function process($id, $requestData, $inboxRequest)
    {
        $connector = $this->getConnector($inboxRequest);
        $remoteCerebrate = $this->getIssuerBrood($inboxRequest);

        $errors = [];
        $connectorResult = [];
        $thrownErrorMessage = '';
        try {
            $connectorResult = $this->finaliseConnection($connector, $remoteCerebrate, $inboxRequest['data']);
            $connectionSuccessfull = !empty($connectorResult['success']);
        } catch (\Throwable $th) {
            $connectionSuccessfull = false;
            $errors = $th->getMessage();
        }
        $resultTitle = __('Could not finalise inter-connection for `{0}`\'s {1}', $inboxRequest['origin'], $inboxRequest['local_tool_name']);
        $errors = $connectorResult['errors'] ?? $thrownErrorMessage;
        if ($connectionSuccessfull) {
            $resultTitle = __('Interconnection for `{0}`\'s {1} finalised', $inboxRequest['origin'], $inboxRequest['local_tool_name']);
            $this->discard($id, $requestData);
        }
        return $this->genActionResult(
            $connectorResult,
            $connectionSuccessfull,
            $resultTitle,
            $errors
        );
    }

    public function discard($id, $requestData)
    {
        return parent::discard($id, $requestData);
    }

    protected function finaliseConnection($connector, $remoteCerebrate, $requestData)
    {
        $connection = $this->getConnection($requestData);
        $params = $this->genBroodParam($remoteCerebrate, $connection, $connector, $requestData);
        $connectorResult = $connector->finaliseConnectionWrapper($params);
        return [
            'success' => true
        ];
    }
}

class DeclinedRequestProcessor extends LocalToolInboxProcessor implements GenericInboxProcessorActionI {
    public $action = 'DeclinedRequest';
    protected $description;

    public function __construct() {
        parent::__construct();
        $this->description = __('Handle Phase II of MISP inter-connection when initial request has been declined by the remote cerebrate.');
    }

    protected function addValidatorRules($validator)
    {
        return $this->addBaseValidatorRules($validator);
    }
    
    public function create($requestData) {
        $this->validateConnectorName($requestData);
        $this->validateRequestData($requestData);
        $connectorMeta = $this->getConnectorMetaFromClassname($requestData['data']['connectorName']);
        $requestData['title'] = __('Declined inter-connection for {0}', $connectorMeta['name']);
        return parent::create($requestData);
    }

    public function getViewVariables($request)
    {
        $request = $this->attachRequestAssociatedData($request);
        return [
            'request' => $request,
            'progressStep' => 1,
            'progressVariant' => 'danger',
            'steps' => [
                1 => ['icon' => 'times', 'text' => __('Request Declined'), 'confirmButton' => __('Clean-up')],
                2 => ['icon' => 'trash', 'text' => __('Clean-up')],
            ]
        ];
    }

    public function process($id, $requestData, $inboxRequest)
    {
        $connectionSuccessfull = false;
        $interConnectionResult = [];
        if ($connectionSuccessfull) {
            $this->discard($id, $requestData);
        }
        return $this->genActionResult(
            $interConnectionResult,
            $connectionSuccessfull,
            $connectionSuccessfull ? __('Interconnection for `{0}`\'s {1} finalised', $requestData['origin'], $requestData['local_tool_name']) : __('Could not inter-connect `{0}`\'s {1}', $requestData['origin'], $requestData['local_tool_name']),
            []
        );
    }
    public function discard($id, $requestData)
    {
        return parent::discard($id, $requestData);
    }
}
