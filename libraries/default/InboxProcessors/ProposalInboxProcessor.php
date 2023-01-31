<?php
use Cake\ORM\TableRegistry;

require_once(ROOT . DS . 'libraries' . DS . 'default' . DS . 'InboxProcessors' . DS . 'GenericInboxProcessor.php'); 

class ProposalInboxProcessor extends GenericInboxProcessor
{
    protected $scope = 'Proposal';
    protected $action = 'not-specified'; //overriden when extending
    protected $description = ''; // overriden when extending
    protected $registeredActions = [
        'ProposalEdit'
    ];

    public function __construct($loadFromAction=false) {
        parent::__construct($loadFromAction);
    }

    public function create($requestData)
    {
        return parent::create($requestData);
    }
}

class ProposalEditProcessor extends ProposalInboxProcessor implements GenericInboxProcessorActionI {
    public $action = 'ProposalEdit';
    protected $description;

    public function __construct() {
        parent::__construct();
        $this->description = __('Handle proposal from users for this cerebrate instance');
        $this->Users = TableRegistry::getTableLocator()->get('Users');
    }

    protected function addValidatorRules($validator)
    {
        return $validator;
    }
    
    public function create($requestData) {
        $this->validateRequestData($requestData);
        $requestData['title'] = __('User `{0}` would like to modify record `{0}`', 'username', 'recordname');
        return parent::create($requestData);
    }

    public function process($id, $requestData, $inboxRequest)
    {
        $proposalAccepted = false;
        $saveResult = [];
        if ($proposalAccepted) {
            $this->discard($id, $requestData);
        }
        return $this->genActionResult(
            $saveResult,
            $proposalAccepted,
            $proposalAccepted ? __('Record `{0}` modify', 'recordname') : __('Could modify record `{0}`.', 'recordname'),
            []
        );
    }

    public function discard($id, $requestData)
    {
        return parent::discard($id, $requestData);
    }
}