<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_tag_if extends WorkflowBaseLogicModule
{
    public $id = 'tag-if';
    public $name = 'IF :: Tag';
    public $description = 'Tag IF / ELSE condition block. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $params = [];

    private $Tag;
    private $operators = [
        'in_or' => 'Is tagged with any (OR)',
        'in_and' => 'Is tagged with all (AND)',
        'not_in_or' => 'Is not tagged with any (OR)',
        'not_in_and' => 'Is not tagged with all (AND)',
    ];

    private const CONTEXT_EVENT = 'event';
    private const CONTEXT_ATTRIBUTE = 'attribute';
    private const CONTEXT_UNKOWN = 'unkown';

    public function __construct()
    {
        parent::__construct();
        $conditions = [
            'Tag.is_galaxy' => 0,
        ];
        $this->Tag = ClassRegistry::init('Tag');
        $tags = $this->Tag->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => ['name asc'],
            'fields' => ['Tag.id', 'Tag.name']
        ]);
        $tags = array_column(array_column($tags, 'Tag'), 'name', 'id');
        $this->params = [
            [
                'type' => 'select',
                'options' => [
                    'event' => __('Event'),
                    'attribute' => __('Attribute'),
                ],
                'default' => 'event',
                'label' => 'Scope',
            ],
            [
                'type' => 'select',
                'label' => 'Condition',
                'default' => 'in_or',
                'options' => $this->operators,
            ],
            [
                'type' => 'picker',
                'multiple' => true,
                'label' => 'Tags',
                'options' => $tags,
                'placeholder' => __('Pick a tag'),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);

        $value = $params['Tags']['value'];
        $operator = $params['Condition']['value'];
        $scope = $params['Scope']['value'];
        $data = $roamingData->getData();
        $path = $this->__getPath($scope, $data);
        $extracted = Hash::extract($data, $path);
        $eval = $this->evaluateCondition($extracted, $operator, $value);
        return !empty($eval);
    }

    /**
     * __getPath
     *
     * @param string $scope
     * @param array $data Data in the MISP core format. Can be coming from multiple context such as Event, Attribute, ..
     * @return false|string
     */
    private function __getPath($scope, array $data)
    {
        $path = false;
        $context = $this->__deduceContextFromData($data);
        if ($scope == 'attribute') {
            if ($context == self::CONTEXT_ATTRIBUTE) {
                $path = 'Attribute.Tag.{n}.id';
            } elseif ($context == self::CONTEXT_EVENT) {
                $path = 'Event.Attribute.Tag.{n}.id';
            }
        } else {
            $scope = 'event';
            if ($context == self::CONTEXT_ATTRIBUTE) {
                $path = 'Attribute.Tag.{n}[inherited=1].id';
            } elseif ($context == self::CONTEXT_EVENT) {
                $path = 'Event.Tag.{n}.id';
            }
        }
        return $path;
    }

    /**
     * __deduceContextFromData
     *
     * @param array $data
     * @return string
     */
    private function __deduceContextFromData(array $data)
    {
        if (!empty($data['Event'])) {
            return self::CONTEXT_EVENT;
        } elseif (!empty($data['Attribute'])) {
            return self::CONTEXT_ATTRIBUTE;
        } else {
            self::CONTEXT_UNKOWN;
        }
    }
}
