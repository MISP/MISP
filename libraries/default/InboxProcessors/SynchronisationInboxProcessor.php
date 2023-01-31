<?php
use Cake\ORM\TableRegistry;

require_once(ROOT . DS . 'libraries' . DS . 'default' . DS . 'InboxProcessors' . DS . 'GenericInboxProcessor.php'); 

class SynchronisationInboxProcessor extends GenericInboxProcessor
{
    protected $scope = 'Synchronisation';
    protected $action = 'not-specified'; //overriden when extending
    protected $description = ''; // overriden when extending
    protected $registeredActions = [
        'DataExchange'
    ];

    public function __construct($loadFromAction=false) {
        parent::__construct($loadFromAction);
    }

    public function create($requestData)
    {
        return parent::create($requestData);
    }
}

class DataExchangeProcessor extends SynchronisationInboxProcessor implements GenericInboxProcessorActionI {
    public $action = 'DataExchange';
    protected $description;

    public function __construct() {
        parent::__construct();
        $this->description = __('Handle exchange of data between two cerebrate instances');
        $this->Users = TableRegistry::getTableLocator()->get('Users');
    }

    protected function addValidatorRules($validator)
    {
        return $validator;
    }
    
    public function create($requestData) {
        $this->validateRequestData($requestData);
        $requestData['title'] = __('Data exchange requested for record `{0}`', 'recordname');
        return parent::create($requestData);
    }

    public function process($id, $requestData, $inboxRequest)
    {
        $dataExchangeAccepted = false;
        $saveResult = [];
        if ($dataExchangeAccepted) {
            $this->discard($id, $requestData);
        }
        return $this->genActionResult(
            $saveResult,
            $dataExchangeAccepted,
            $dataExchangeAccepted ? __('Record `{0}` exchanged', 'recordname') : __('Could not exchange record `{0}`.', 'recordname'),
            []
        );
    }

    public function discard($id, $requestData)
    {
        return parent::discard($id, $requestData);
    }
}