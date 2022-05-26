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
        if (!empty($matchingUUID)) {
            $this->propagateConditions($roamingData, $ifScope, $matchingUUID);
        }
        return !empty($matchingUUID);
    }

    public function getMatchingUUID(array $user, $model, array $data, array $filters): array
    {
        if (!in_array($model, array_keys($this->allowedScopes))) {
            $this->logError(__('Unknown model %s', $model));
            return [];
        }
        $loadedModel = ClassRegistry::init($model);
        if (empty($user)) {
            return [];
        }
        if ($model == 'Event') {
            if (!empty($data['Event.uuid'])) {
                $filters['uuid'] = $data['Event.uuid'];
            }
            $filters['metadata'] = true;
        } elseif ($model == 'Attribute') {
            if (!empty($data['Event.uuid'])) {
                $filters['eventid'] = $data['Event.uuid'];
            }
            if (!empty($data['Attribute.uuid'])) {
                $filters['uuid'] = $data['Attribute.uuid'];
            }
        }
        $final = $loadedModel->restSearch($user, 'json', $filters);
        $result = json_decode($final->intoString(), true)['response'];
        $matchingUUID = [];
        if ($model == 'Event') {
            $matchingUUID = Hash::extract($result, '{n}.Event.uuid');
        } elseif ($model == 'Attribute') {
            $matchingUUID = Hash::extract($result, 'Attribute.{n}.uuid');
        }
        return $matchingUUID;
    }

    public function propagateConditions(WorkflowRoamingData $roamingData, $scope, array $matchingUUID)
    {
        $data = $roamingData->getData();
        if ($scope == 'Event') {
            $data['Event.uuid'] = $matchingUUID;
        } elseif ($scope == 'Attribute') {
            $data['Attribute.uuid'] = $matchingUUID;
        }
        $roamingData->setData($data);
    }
}
