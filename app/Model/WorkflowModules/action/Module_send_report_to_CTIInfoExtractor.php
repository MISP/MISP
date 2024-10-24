<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_send_report_to_CTIInfoExtractor extends WorkflowBaseActionModule
{
    public $id = 'send-report-to-cti-info-extractor';
    public $name = 'Send Report to CTI Info Extractor';
    public $version = '0.1';
    public $description = 'Send selected Event Report to the CTI Info Extractor Endpoint';
    public $icon = 'robot';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $EventReport;


    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'insert_executive_summary',
                'label' => 'Insert Executive Summary',
                'type' => 'select',
                'options' => [
                    'no' => 'No',
                    'yes' => 'Yes',
                ],
                'default' => 'yes',
            ],
            [
                'id' => 'tag_event_with_threat_actor',
                'label' => 'Tag Event with Threat Actor',
                'type' => 'select',
                'options' => [
                    'no' => 'No',
                    'yes' => 'Yes',
                ],
                'default' => 'yes',
            ],
            [
                'id' => 'tag_event_with_threat_actor_country',
                'label' => 'Tag Event with Threat Actor Country',
                'type' => 'select',
                'options' => [
                    'no' => 'No',
                    'yes' => 'Yes',
                ],
                'default' => 'yes',
            ],
            [
                'id' => 'tag_event_with_threat_actor_motivation',
                'label' => 'Tag Event with Threat Actor Motivation',
                'type' => 'select',
                'options' => [
                    'no' => 'No',
                    'yes' => 'Yes',
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
        $filters = $this->getFilters($node);
        $extracted = $this->extractData($rData, $filters['selector']);
        if ($extracted === false) {
            return false;
        }
        $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);

        $options = [
            'insert_executive_summary' => $params['insert_executive_summary']['value'] === 'yes',
            'tag_event_with_threat_actor' => $params['tag_event_with_threat_actor']['value'] === 'yes',
            'tag_event_with_threat_actor_country' => $params['tag_event_with_threat_actor_country']['value'] === 'yes',
            'tag_event_with_threat_actor_motivation' => $params['tag_event_with_threat_actor_motivation']['value'] === 'yes',
        ];

        $this->EventReport = ClassRegistry::init('EventReport');
        $eventReports = !empty($matchingItems['Event']['EventReport']) ? $matchingItems['Event']['EventReport'] : [];
        foreach ($eventReports as $report) {
            $result = $this->EventReport->sendToLLM($report, $roamingData->getUser(), $errors, $options);
        }
        return true;
    }
}
