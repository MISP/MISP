<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_threat_level_if extends WorkflowBaseLogicModule
{
    public $id = 'threat-level-if';
    public $name = 'IF :: Threat Level';
    public $version = '0.1';
    public $description = 'Threat Level IF / ELSE condition block. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';

    private $Event;

    private $operators = [
        'equals' => 'Is',
        'not_equals' => 'Is not',
        'greater_or_equal_than' => 'Greater or equal than',
        'less_or_equal_than' => 'Less or equal than',
    ];
    private $threatlevels_mapping;

    public function __construct()
    {
        parent::__construct();
	$this->Event = ClassRegistry::init('Event');
	$this->threatlevels_mapping = $this->Event->ThreatLevel->listThreatLevels();

        $this->params = [
            [
                'id' => 'condition',
                'label' => 'Condition',
                'type' => 'select',
                'default' => 'equals',
                'options' => $this->operators,
            ],
            [
                'id' => 'threatlevel',
                'label' => 'Threat Level',
                'type' => 'select',
		'default' => 'Low',
                'options' => $this->threatlevels_mapping,
                'placeholder' => __('Pick a threat level'),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $data = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $data);

	    $operator = $params['condition']['value'];
        $selected_threatlevel = $params['threatlevel']['value'];

	$threatlevel_id = $data['Event']['threat_level_id'];

	if ($operator == 'equals') {
	    if ($threatlevel_id == $selected_threatlevel) {
		return true;
	    } else {
		return false;
	    }
	} 

	if ($operator == 'not_equals') {
	    if ($threatlevel_id != $selected_threatlevel) {
		return true;
	    } else {
		return false;
	    }
	}

	if ($operator == 'greater_or_equal_than') {
	    if($threatlevel_id <= $selected_threatlevel) {
		return true;
	    } else {
		return false;
	    }
	}

	if ($operator == 'less_or_equal_than') {
	    if($threatlevel_id >= $selected_threatlevel) {
		return true;
	    } else {
		return false;
	    }
	}

	return false;
    }

}
