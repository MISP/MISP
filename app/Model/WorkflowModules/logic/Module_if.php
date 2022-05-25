<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_if extends WorkflowBaseModule
{
    public $id = 'if';
    public $name = 'IF';
    public $description = 'Simple IF / ELSE condition block. Use the `then` output for execution path satifying the conditions passed to the `IF` block.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'IF';
    public $params = [];

    private $allowedScopes = [
        'Event' => 'Event',
        'Attribute' => 'Attribute',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'select',
                'label' => 'Scope',
                'default' => 'Event',
                'options' => $this->allowedScopes,
            ],
            [
                'type' => 'textarea',
                'label' => 'Matching Conditions',
                'default' => '',
                'placeholder' => '{ "tags" : { "AND" : [ "tlp : green" , "Malware" ] , "NOT" : [ "%ransomware%" ]}}'
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData): bool
    {
        parent::exec($node, $roamingData);
        $params = $this->getParamsWithValues($node);
        $ifScope = $params['Scope']['value'];
        $ifFilter = json_decode($params['Matching Conditions']['value'], true);
        $matchingUUID = $this->getMatchingUUID($roamingData->getUser(), $ifScope, $roamingData->getData(), $ifFilter);
        return !empty($matchingUUID);
    }

    public function getMatchingUUID(array $user, $model, array $data, array $filters): array
    {
        if (!in_array($model, array_keys($this->allowedScopes))) {
            $this->logError(__('Unknown model %s', $model));
            return [];
        }
        $loadedMode = ClassRegistry::init($model);
        if (empty($user) || empty($data['uuid'])) {
            return [];
        }
        $filters['uuid'] = $data['uuid'];
        $final = $loadedMode->restSearch($user, 'json', $filters);
        $events = json_decode($final->intoString(), true)['response'];
        $matchingUUID = Hash::extract($events, '{n}.Event.uuid');
        return $matchingUUID;
    }
}
