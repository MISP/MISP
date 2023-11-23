<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_tag_if extends WorkflowBaseLogicModule
{
    public $id = 'tag-if';
    public $name = 'IF :: Tag';
    public $version = '0.4';
    public $description = 'Tag IF / ELSE condition block. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $expect_misp_core_format = true;
    public $params = [];

    private $Tag;
    private $operators = [
        'in_or' => 'Is tagged with any (OR)',
        'in_and' => 'Is tagged with all (AND)',
        'not_in_or' => 'Is not tagged with any (OR)',
        'not_in_and' => 'Is not tagged with all (AND)',
    ];

    private function getDisplayTag($fullTag)
    {
        return substr($fullTag, 12);
    }

    public function __construct()
    {
        parent::__construct();
        $conditions = [
            'Tag.is_galaxy' => [0, 1],
        ];
        $this->Tag = ClassRegistry::init('Tag');
        $allTags = $this->Tag->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => ['name asc'],
            'fields' => ['Tag.id', 'Tag.name', 'Tag.is_galaxy']
        ]);
        $tags = [];
        $clusters = [];
        foreach ($allTags as $tag) {
            if ($tag['Tag']['is_galaxy']) {
                $readableTagName = $this->getDisplayTag($tag['Tag']['name']);
                $clusters[] = $readableTagName;
            } else {
                $tags[] = $tag['Tag']['name'];
            }
        }
        $this->params = [
            [
                'id' => 'scope',
                'label' => 'Scope',
                'type' => 'select',
                'options' => [
                    'event' => __('Event'),
                    'attribute' => __('Attribute'),
                    'event_attribute' => __('Inherited Attribute'),
                ],
                'default' => 'event',
            ],
            [
                'id' => 'condition',
                'label' => 'Condition',
                'type' => 'select',
                'default' => 'in_or',
                'options' => $this->operators,
            ],
            [
                'id' => 'tags',
                'label' => 'Tags',
                'type' => 'picker',
                'multiple' => true,
                'options' => $tags,
                'placeholder' => __('Pick a tag'),
            ],
            [
                'id' => 'clusters',
                'label' => __('Galaxy Clusters'),
                'type' => 'picker',
                'multiple' => true,
                'options' => $clusters,
                'placeholder' => __('Pick a Galaxy Cluster'),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $data = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $data);

        $selectedTags = !empty($params['tags']['value']) ? $params['tags']['value'] : [];
        $selectedClusters = !empty($params['clusters']['value']) ? $params['clusters']['value'] : [];
        $selectedClusters = array_map(function($tagName) {
            return "misp-galaxy:{$tagName}"; // restored stripped part for display purposes
        }, $selectedClusters);
        $allSelectedTags = array_merge($selectedTags, $selectedClusters);
        $operator = $params['condition']['value'];
        $scope = $params['scope']['value'];
        $extracted = $this->__getTagFromScope($scope, $data);
        $eval = $this->evaluateCondition($extracted, $operator, $allSelectedTags);
        return !empty($eval);
    }

    private function __getTagFromScope($scope, array $data): array
    {
        $path = '';
        if ($scope == 'attribute') {
            $path = 'Event._AttributeFlattened.{n}.Tag.{n}.name';
        } elseif ($scope == 'event_attribute') {
            $path = 'Event._AttributeFlattened.{n}._allTags.{n}.name';
        } else {
            $path = 'Event.Tag.{n}.name';
        }
        return Hash::extract($data, $path) ?? [];
    }
}
