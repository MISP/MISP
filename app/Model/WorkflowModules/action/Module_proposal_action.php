<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_proposal_action extends WorkflowBaseActionModule
{
    public $id = 'proposal-action';
    public $name = 'Proposal Action';
    public $version = '0.2';
    public $description = 'Accept or remove any proposals being passed';
    public $icon = 'asterisk';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Module;


    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'action',
                'label' => 'Action',
                'type' => 'select',
                'options' => [
                    'accept' => 'Accept Proposals',
                    'remove' => 'Remove Proposals',
                ],
                'default' => 'accept',
            ],
            [
                'id' => 'proposal_type',
                'label' => 'Proposal Type',
                'type' => 'select',
                'options' => [
                    'new' => 'Proposals to create new Attributes',
                    'edit' => 'Proposals on existing Attributes',
                    'any' => 'Any type of Proposals',
                ],
                'default' => 'all',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $action = $params['action']['value'];
        $proposal_type = $params['proposal_type']['value'];

        if ($this->filtersEnabled($node)) {
            $filters = $this->getFilters($node);
            $extracted = $this->extractData($rData, $filters['selector']);
            if ($extracted === false) {
                return false;
            }
            $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
            if ($this->filtersEnabled($node) && empty($matchingItems)) {
                return true; // Filters are enabled and no matching items was found
            }
        } else {
            $matchingItems = $rData;
        }
        
        $this->ShadowAttribute = ClassRegistry::init('ShadowAttribute');
        $matchingProposals = [];
        if ($proposal_type == 'new') {
            $matchingProposals = Hash::extract($matchingItems, 'Event.ShadowAttribute.{n}');
        } else if ($proposal_type == 'edit') {
            $matchingProposals = Hash::extract($matchingItems, 'Event._AttributeFlattened.{n}.ShadowAttribute.{n}');
        } else if ($proposal_type == 'any') {
            $matchingProposals = array_merge(
                Hash::extract($matchingItems, 'Event.ShadowAttribute.{n}'),
                Hash::extract($matchingItems, 'Event._AttributeFlattened.{n}.ShadowAttribute.{n}')
            );
        } else {
            $matchingProposals = [];
        }

        $user = $roamingData->getUser();
        $reloadRoamingData = !empty($matchingProposals);

        $result = true;
        foreach ($matchingProposals as $proposal) {
            if ($action == 'accept') {
                $proposal = ['ShadowAttribute' => $proposal];
                $result = $this->ShadowAttribute->acceptProposal($user, $proposal)['success'] || $result ;
            } else {
                $proposal = ['ShadowAttribute' => $proposal];
                $result = $this->ShadowAttribute->discardProposal($user, $proposal) || $result ;
            }
        }
        
        if ($reloadRoamingData) {
            $this->reloadRoamingData($roamingData);
        }
        return $result;
    }
}
