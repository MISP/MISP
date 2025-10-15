<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_run_workflow extends WorkflowBaseActionModule
{
    public $id = 'run-workflow';
    public $name = 'Run Workflow';
    public $version = '0.1';
    public $description = 'Run a Workflow.';
    public $icon = 'project-diagram';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Workflow;
    private $workflowNameProxy = [];


    public function __construct()
    {
        parent::__construct();
        $this->Workflow = ClassRegistry::init('Workflow');
        $workflows = $this->Workflow->fetchAdHocWorkflows();
        $workflowOptions = [];
        foreach ($workflows as $workflow) {
            $niceName = sprintf('%s :: %s', $workflow['Workflow']['trigger_id'], $workflow['Workflow']['name']);
            $workflowOptions[$workflow['Workflow']['id']] = $niceName;
            $this->workflowNameProxy[$niceName] = $workflow['Workflow']['id'];
        }
        sort($workflowOptions);
        $this->params = [
            [
                'id' => 'workflows',
                'label' => 'Workflows',
                'type' => 'picker',
                'options' => $workflowOptions,
                'multiple' => true,
            ],
            [
                'id' => 'input_data',
                'label' => 'Select Data passed to Workflow',
                'type' => 'select',
                'options' => [
                    'nothing' => 'No data passed',
                    'roaming_data' => 'Roaming Data (Data of this Workflow)',
                    'event_ids' => 'Event IDs from filters or Extracted from Roaming Data'
                ],
                'default' => 'yes',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $input_data = $params['input_data']['value'];
        if (empty($params['workflows']['value'])) {
            $errors[] = __('No workflow selected');
            return false;
        }

        $payload = [];
        if ($input_data == 'nothing') {
            $payload = [];
        } else if ($input_data == 'roaming_data') {
            $payload = $rData;
        } else if ($input_data == 'event_ids') {
            $event_uuids = $this->getEventUUIDS($node, $rData);
            if (empty($event_uuids)) {
                return false;
            }
            $payload = [
                'eventid' => $event_uuids,
            ];
        }

        foreach ($params['workflows']['value'] as $workflowName) {
            $workflowID = $this->workflowNameProxy[$workflowName];
            $this->Workflow->executeWorkflow($workflowID, $payload);
        }
        $this->reloadRoamingData($roamingData);
        return true;
    }

    private function getEventUUIDS($node, $rData)
    {
        $event_uuids = [];
        $filters = $this->getFilters($node);
        $extracted = $this->extractData($rData, $filters['selector']);
        if ($extracted === false) {
            return false;
        }
        $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
        if ($this->filtersEnabled($node) && empty($matchingItems)) {
            return true; // Filters are enabled and no matching items was found
        } else if ($this->filtersEnabled($node) && !empty($matchingItems)) {
            $extractedUUIDs = $this->extractData($matchingItems, '{n}.uuid');
            if ($extractedUUIDs === false) {
                return false;
            }
            $event_uuids = $extractedUUIDs;
        } else {
            $extractedUUIDs = Hash::extract($rData, 'Event.uuid');
            if ($extractedUUIDs === false) {
                return false;
            }
            $event_uuids = $extractedUUIDs;
        }
        return $event_uuids;
    }
}
