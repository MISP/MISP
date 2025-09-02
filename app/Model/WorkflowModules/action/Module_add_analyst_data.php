<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_add_analyst_data extends WorkflowBaseActionModule
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'add_analyst_data';
    public $name = 'Add Analyst Data';
    public $description = 'Add analyst data on the selected element(s).';
    public $icon = 'sticky-note';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Note;
    private $Opinion;
    private $Relationship;
    private $MispAttribute;
    private $SharingGroup;

    private $validTargets = [
        'Attribute',
        'Event',
        'EventReport',
        'GalaxyCluster',
        'Object',
    ];


    public function __construct()
    {
        parent::__construct();
        $conditions = [
            'Tag.is_galaxy' => 0,
        ];
        $this->Note = ClassRegistry::init('Note');
        $this->Opinion = ClassRegistry::init('Opinion');
        $this->Relationship = ClassRegistry::init('Relationship');
        $this->MispAttribute = ClassRegistry::init('MispAttribute');
        $this->SharingGroup = ClassRegistry::init('SharingGroup');

        
        $validTypes = array_combine($this->Note::ANALYST_DATA_TYPES, $this->Note::ANALYST_DATA_TYPES);

        $distributionLevels = $this->MispAttribute->shortDist;
        $distribution_param = [];
        foreach ($distributionLevels as $i => $text) {
            $distribution_param[] = ['name' => $text, 'value' => $i];
        }

        $sharing_groups = Hash::combine($this->SharingGroup->fetchAllSharingGroup(), '{n}.SharingGroup.id', '{n}.SharingGroup.name');


        $this->params = [
            [
                'id' => 'target',
                'label' => __('Target'),
                'type' => 'select',
                'options' => $this->validTargets,
                'default' => 'Event',
            ],
            [
                'id' => 'analyst_data_type',
                'label' => __('Analyst Data Type'),
                'type' => 'select',
                'options' => $validTypes,
                'default' => 'Note',
            ],
            [
                'id' => 'distribution',
                'label' => 'Distribution',
                'type' => 'select',
                'default' => '0',
                'options' => $distribution_param,
                'placeholder' => __('Pick a distribution'),
            ],
            [
                'id' => 'sharing_group_id',
                'label' => 'Sharing Groups',
                'type' => 'picker',
                'multiple' => false,
                'options' => $sharing_groups,
                'default' => [],
                'placeholder' => __('Pick a sharing group'),
                'display_on' => [
                    'distribution' => '4',
                ],
            ],
            [
                'id' => 'author',
                'label' => __('Author'),
                'type' => 'input',
            ],

            // NOTE
            [
                'id' => 'language',
                'label' => __('Language'),
                'type' => 'input',
                'display_on' => [
                    'analyst_data_type' => 'Note',
                ],
            ],
            [
                'id' => 'note',
                'label' => __('Note'),
                'type' => 'textarea',
                'jinja_supported' => true,
                'display_on' => [
                    'analyst_data_type' => 'Note',
                ],
            ],

            // OPINION
            [
                'id' => 'opinion',
                'label' => __('Opinion'),
                'type' => 'input',
                'input_type' => 'number',
                'min' => 0,
                'max' => 100,
                'display_on' => [
                    'analyst_data_type' => 'Opinion',
                ],
            ],
            [
                'id' => 'comment',
                'label' => __('Comment'),
                'type' => 'textarea',
                'jinja_supported' => true,
                'display_on' => [
                    'analyst_data_type' => 'Opinion',
                ],
            ],

            // RELATIONSHIP
            [
                'id' => 'relationship_type',
                'label' => __('Relationship Type'),
                'type' => 'input',
                'jinja_supported' => true,
                'display_on' => [
                    'analyst_data_type' => 'Relationship',
                ],
            ],
            [
                'id' => 'related_object_type',
                'label' => __('Related Object Type'),
                'type' => 'input',
                'jinja_supported' => true,
                'placeholder' => __('Use one of the valid targets from the target list'),
                'default' => 'Event',
                'display_on' => [
                    'analyst_data_type' => 'Relationship',
                ],
            ],
            [
                'id' => 'related_object_uuid',
                'label' => __('Related Object UUID'),
                'type' => 'input',
                'jinja_supported' => true,
                'display_on' => [
                    'analyst_data_type' => 'Relationship',
                ],
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $user = $roamingData->getUser();

        $matchingItems = $rData;
        if ($this->filtersEnabled($node)) {
            $filters = $this->getFilters($node);
            $extracted = $this->extractData($rData, $filters['selector']);
            if ($extracted === false) {
                return false;
            }
            $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
        } else {
            $matchingItems = $rData;
            if ($params['target']['value'] == 'Event') {
                $matchingItems = $matchingItems;
            } else if ($params['target']['value'] == 'Attribute') {
                $matchingItems = Hash::get($matchingItems, 'Event._AttributeFlattened');
            } else if ($params['target']['value'] == 'EventReport') {
                $matchingItems = Hash::get($matchingItems, 'Event.EventReport');
            } else if ($params['target']['value'] == 'Object') {
                $matchingItems = Hash::get($matchingItems, 'Event.Object');
            } else if ($params['target']['value'] == 'GalaxyCluster') {
                $matchingItems = Hash::get($matchingItems, 'Event.GalaxyCluster');
            }
        }

        $result = false;
        $options = [
            'target' => $params['target']['value'],
            'distribution' => $params['distribution']['value'],
            'sharing_group_id' => $params['distribution']['value'] != '4' ? $params['sharing_group_id']['value'] : 0,
            'author' => $params['author']['value'],
        ];
        if ($params['analyst_data_type']['value'] == 'Note') {
            $options['language'] = $params['language']['value'];
            $options['note'] = $params['note']['value'];
            $result = $this->__addNotes($matchingItems, $options, $user);
        } else if ($params['analyst_data_type']['value'] == 'Opinion') {
            $options['opinion'] = $params['opinion']['value'];
            $options['comment'] = $params['comment']['value'];
            $result = $this->__addOpinions($matchingItems, $options, $user);
        } else if ($params['analyst_data_type']['value'] == 'Relationship') {
            $options['relationship_type'] = $params['relationship_type']['value'];
            $options['related_object_type'] = $params['related_object_type']['value'];
            $options['related_object_uuid'] = $params['related_object_uuid']['value'];
            $result = $this->__addRelationships($matchingItems, $options, $user);
        }
        return $result;
    }

    protected function __generateAnalystData($type, array $options): array
    {
        $analystData = $options;
        return [$type => $analystData];
    }

    protected function __addNotes(array $matchingItems, array $options, array $user): bool
    {
        $success = false;
        foreach ($matchingItems as $matchingItem) {
            $options['object_type'] = $options['target'];
            $options['object_uuid'] = $matchingItem['uuid'];
            if (!Validation::uuid($options['object_uuid'])) {
                continue;
            }
            $analystData = $this->__generateAnalystData('Note', $options);
            $saveSuccess = $this->Note->captureAnalystData($user, $analystData);
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }
    
    protected function __addOpinions(array $matchingItems, array $options, array $user): bool
    {
        $success = false;
        foreach ($matchingItems as $matchingItem) {
            $options['object_type'] = $options['target'];
            $options['object_uuid'] = $matchingItem['uuid'];
            if (!Validation::uuid($options['object_uuid'])) {
                continue;
            }
            $analystData = $this->__generateAnalystData('Opinion', $options);
            $saveSuccess = $this->Opinion->captureAnalystData($user, $analystData);
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }

    protected function __addRelationships(array $matchingItems, array $options, array $user): bool
    {
        $success = false;
        foreach ($matchingItems as $matchingItem) {
            $options['object_type'] = $options['target'];
            $options['object_uuid'] = $matchingItem['uuid'];
            if (!Validation::uuid($options['object_uuid'])) {
                continue;
            }
            $analystData = $this->__generateAnalystData('Relationship', $options);
            $saveSuccess = $this->Relationship->captureAnalystData($user, $analystData);
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }
}
