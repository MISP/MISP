<?php
include_once APP . 'Model/WorkflowModules/action/Module_webhook.php';

class Module_flowintel_create_case extends Module_webhook
{
    public $id = 'flowintel-create-case';
    public $name = 'Flowintel :: Create case';
    public $version = '0.5';
    public $description = 'Perform callbacks to the MS Teams webhook provided by the "Incoming Webhook" connector';
    public $icon_path = 'flowintel_logo.png';

    private WorkflowRoamingData $currentRoamingData;
    private $currentNode;
    private $MispObject;

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'url',
                'label' => 'Flowintel URL',
                'type' => 'input',
                'placeholder' => 'https://flowintel-url.test',
            ],
            [
                'id' => 'apikey',
                'label' => 'Flowintel API Key',
                'type' => 'input',
                'placeholder' => 'W4PWn54LzJ71TY55PzxChVBl4tyPuIkMPZ5iC0hRrSkQGfjF0pTYLp6CnHBP',
            ],
            [
                'id' => 'create-reference',
                'label' => __('Create reference'),
                'type' => 'select',
                'default' => 'yes',
                'options' => [
                    'yes' => 'Reference the case in the Event',
                    'no' => 'Do not reference the case',
                ],
            ],
            [
                'id' => 'case-name',
                'label' => __('Case name'),
                'type' => 'textarea',
                'default' => '{{ Event.info }}',
                'placeholder' => '{{ Event.info }}',
                'jinja_supported' => true,
            ],
        ];

        $this->MispObject = ClassRegistry::init('MispObject');
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        $this->currentRoamingData = $roamingData;
        $this->currentNode = $node;

        $rData = $this->currentRoamingData->getData();
        $params = $this->getParamsWithValues($this->currentNode, $rData);
        if (empty($params['url']['value']) || empty($params['apikey']['value'])) {
            $errors[] = __('No URL or API Key');
            return false;
        }
        return parent::exec($node, $roamingData, $errors);
    }

    protected function doRequest($url, $contentType, $data, $headers = [], $requestMethod='post', $serverConfig = null)
    {
        $rData = $this->currentRoamingData->getData();
        $params = $this->getParamsWithValues($this->currentNode, $rData);

        $caseTitle = !empty($params['case-name']['value']) ? $params['case-name']['value'] : $rData['Event']['info'];
        $data = [
            'title' => $caseTitle,
            'description' => sprintf('Case created for MISP Event %s', $rData['Event']['uuid']),
            'ticket_id' => $rData['Event']['uuid'],
            'event' => $rData,
            'origin_url' => $rData['_env']['baseurl'],
        ];
        $headers = [
            'X-API-KEY' => $params['apikey']['value'],
        ];
        $fullUrl = $url . '/api/case/create_with_event';
        $response = parent::doRequest($fullUrl, $contentType, $data, $headers, $requestMethod, $serverConfig);
        if ($response->isOk()) {
            $caseResult = json_decode($response->body(), true);
            $this->saveReference($caseResult, $rData['Event']['id']);
        }
        return $response;
    }

    protected function saveReference($case, $eventId)
    {
        $rData = $this->currentRoamingData->getData();
        $params = $this->getParamsWithValues($this->currentNode, $rData);

        if ($params['create-reference']['value'] == 'no') {
            return;
        }

        $caseTitle = !empty($params['case-name']['value']) ? $params['case-name']['value'] : $rData['Event']['info'];

        $eventId = $this->currentRoamingData->getData()['Event']['id'];
        $object = [
            'Object' => [
                'name' => 'flowintel-case',
                'meta-category' => 'misc',
                'description' => 'A case as defined by flowintel.',
                'template_version' => 5,
                'template_uuid' => '19df57c7-b315-4fd2-84e5-d81ab221425e',
            ],
            'Attribute' => [
                [
                    'event_id' => $eventId,
                    'type' => 'link',
                    'category' => 'External analysis',
                    'object_relation' => 'flowintel-url',
                    'to_ids' => 0,
                    'value' => sprintf('%s/case/%s', h($params['url']['value']), $case['case_id']),
                ],
                [
                    'event_id' => $eventId,
                    'type' => 'text',
                    'category' => 'Other',
                    'object_relation' => 'case-uuid',
                    'to_ids' => 0,
                    'value' => $case['case_id'],
                ],
                [
                    'event_id' => $eventId,
                    'type' => 'text',
                    'category' => 'Other',
                    'object_relation' => 'title',
                    'to_ids' => 0,
                    'value' => $caseTitle,
                ],
            ],
        ];
        $this->MispObject->saveObject($object, $eventId, false, $this->currentRoamingData->getUser(), 'drop', true);
    }
}
