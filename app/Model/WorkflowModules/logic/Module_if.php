<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_if extends WorkflowBaseModule
{
    public $id = 'if';
    public $name = 'Conditional Switch';
    public $description = 'Simple IF / ELSE condition block. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $params = [];

    private $operators = [
        'in' => 'In',
        'not_in' => 'Not in',
        'equals' => 'Equals',
        'not_equals' => 'Not equals',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'input',
                'label' => 'Value',
                'placeholder' => 'tlp:red',
            ],
            [
                'type' => 'select',
                'label' => 'Operator',
                'default' => 'in',
                'options' => $this->operators,
            ],
            [
                'type' => 'input',
                'label' => 'Hash path',
                'placeholder' => 'Attribute.{n}.Tag',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);
        $path = $params['Hash path']['value'];
        $operator = $params['Operator']['value'];
        $value = $params['Value']['value'];
        $data = $roamingData->getData();
        $extracted = Hash::extract($data, $path);
        $eval = $this->__evaluateCondition($extracted, $operator, $value);
        return !empty($eval);
    }

    // public function __evaluateConditions($extracted, $operator, $value): array
    // {
    //     foreach ($extracted as $i => $item) {
    //         if(!$this->__evaluateCondition($item, $operator, $value)) {
    //             unset($extracted[$i]);
    //         }
    //     }
    //     return $extracted;
    // }

    public function __evaluateCondition($item, $operator, $value): bool
    {
        if ($operator == 'in') {
            return is_array($item) && in_array($value, $item);
        } elseif ($operator == 'not_in') {
            return is_array($item) && !in_array($value, $item);
        } elseif ($operator == 'equals') {
            return is_string($item) && $item == $value;
        } elseif ($operator == 'not_equals') {
            return is_string($item) &&  $item != $value;
        }
        return false;
    }

    // public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    // {
    //     parent::exec($node, $roamingData, $errors);
    //     $params = $this->getParamsWithValues($node);
    //     $ifScope = $params['Scope']['value'];
    //     $ifFilter = JsonTool::decode($params['Matching Conditions']['value'], true);
    //     $this->propagateInitialConditions($roamingData, $ifScope);
    //     $matchingUUID = $this->getMatchingUUID($roamingData->getUser(), $ifScope, $roamingData->getData(), $ifFilter);
    //     if (!empty($matchingUUID)) {
    //         $this->propagateConditions($roamingData, $ifScope, $matchingUUID);
    //     }
    //     return !empty($matchingUUID);
    // }

    // public function getMatchingUUID(array $user, $model, array $data, array $filters): array
    // {
    //     if (!in_array($model, array_keys($this->allowedScopes))) {
    //         $this->logError(__('Unknown model %s', $model));
    //         return [];
    //     }
    //     $loadedModel = ClassRegistry::init($model);
    //     if (empty($user)) {
    //         return [];
    //     }
    //     if ($model == 'Event') {
    //         if (!empty($data['__conditionData']['Event.uuid'])) {
    //             $filters['uuid'] = $data['__conditionData']['Event.uuid'];
    //         }
    //         $filters['metadata'] = true;
    //     } elseif ($model == 'Attribute') {
    //         if (!empty($data['__conditionData']['Event.uuid'])) {
    //             $filters['eventid'] = $data['__conditionData']['Event.uuid'];
    //         }
    //         if (!empty($data['__conditionData']['Attribute.uuid'])) {
    //             $filters['uuid'] = $data['__conditionData']['Attribute.uuid'];
    //         }
    //     }
    //     $final = $loadedModel->restSearch($user, 'json', $filters);
    //     $result = json_decode($final->intoString(), true)['response'];
    //     $matchingUUID = [];
    //     if ($model == 'Event') {
    //         $matchingUUID = Hash::extract($result, '{n}.Event.uuid');
    //     } elseif ($model == 'Attribute') {
    //         $matchingUUID = Hash::extract($result, 'Attribute.{n}.uuid');
    //     }
    //     return $matchingUUID;
    // }

    // public function propagateConditions(WorkflowRoamingData $roamingData, $scope, array $matchingUUID)
    // {
    //     $data = $roamingData->getData();
    //     $conditionData = [];
    //     if ($scope == 'Event') {
    //         $conditionData['Event.uuid'] = $matchingUUID;
    //     } elseif ($scope == 'Attribute') {
    //         $conditionData['Attribute.uuid'] = $matchingUUID;
    //     }
    //     $data['__conditionData'] = $conditionData;
    //     $roamingData->setData($data);
    // }

    // public function propagateInitialConditions(WorkflowRoamingData $roamingData, $scope)
    // {
    //     $data = $roamingData->getData();
    //     if (!empty($data['__conditionData'])) {
    //         return;
    //     }
    //     // We expect data to be of the MISP core format
    //     $matchingUUID = -1;
    //     if ($scope == 'Event') {
    //         $matchingUUID = $data['Event']['uuid'];
    //     } elseif ($scope == 'Attribute') {
    //         if (is_array($data['Attribute'])) {
    //             $matchingUUID = Hash::extract($data['Attribute'], '{n}.uuid');
    //         } else {
    //             $matchingUUID = $data['Attribute']['uuid'];
    //         }
    //     }
    //     $this->propagateConditions($roamingData, $scope, $matchingUUID);
    // }
}
