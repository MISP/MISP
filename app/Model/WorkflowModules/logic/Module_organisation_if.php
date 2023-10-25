<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_organisation_if extends WorkflowBaseLogicModule
{
    public $version = '0.2';
    public $id = 'organisation-if';
    public $name = 'IF :: Organisation';
    public $description = 'Organisation IF / ELSE condition block. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $expect_misp_core_format = true;
    public $params = [];

    private $Organisation;
    private $operators = [
        'in' => 'Is any of (OR)',
        'not_in' => 'Is not any of (OR)',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->Organisation = ClassRegistry::init('Organisation');
        $orgs = $this->Organisation->find('list', [
            'fields' => ['id', 'name'],
            'order' => 'LOWER(name)'
        ]);
        $this->params = [
            [
                'id' => 'org_type',
                'label' => 'Organisation Type',
                'type' => 'select',
                'options' => [
                    'org' => __('Owner Organisation'),
                    'orgc' => __('Creator Organisation'),
                ],
                'default' => 'orgc',
            ],
            [
                'id' => 'condition',
                'label' => 'Condition',
                'type' => 'select',
                'default' => 'in',
                'options' => $this->operators,
            ],
            [
                'id' => 'org_id',
                'type' => 'picker',
                'multiple' => true,
                'options' => $orgs,
                'default' => [1],
                'placeholder' => __('Pick an organisation'),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $data = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $data);

        $org_type = $params['org_type']['value'];
        $operator = $params['condition']['value'];
        $selectedOrgs = !empty($params['org_id']['value']) ? $params['org_id']['value'] : [];
        $selectedOrgs = is_array($selectedOrgs) ? $selectedOrgs : [$selectedOrgs]; // Backward compatibility for non-multiple `org_id`
        $path = 'Event.org_id';
        if ($org_type == 'orgc') {
            $path = 'Event.orgc_id';
        }
        $extracted_org = intval(Hash::get($data, $path)) ?? -1;
        $eval = $this->evaluateCondition($selectedOrgs, $operator, $extracted_org);
        return !empty($eval);
    }
}
