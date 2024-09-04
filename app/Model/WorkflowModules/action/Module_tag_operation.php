<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_tag_operation extends WorkflowBaseActionModule
{
    public $version = '0.2';
    public $blocking = false;
    public $id = 'tag_operation';
    public $name = 'Tag operation';
    public $description = 'Add or remove tags on Event or Attributes.';
    public $icon = 'tags';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Tag;
    private $Event;
    private $Attribute;


    public function __construct()
    {
        parent::__construct();
        $conditions = [
            'Tag.is_galaxy' => 0,
        ];
        $this->Tag = ClassRegistry::init('Tag');
        $this->Event = ClassRegistry::init('Event');
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $tags = $this->Tag->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => ['name asc'],
            'fields' => ['Tag.id', 'Tag.name']
        ]);
        $tags = array_column(array_column($tags, 'Tag'), 'name');
        $this->params = [
            [
                'id' => 'scope',
                'label' => __('Scope'),
                'type' => 'select',
                'options' => [
                    'event' => __('Event'),
                    'attribute' => __('Attributes'),
                ],
                'default' => 'event',
            ],
            [
                'id' => 'action',
                'label' => __('Action'),
                'type' => 'select',
                'options' => [
                    'add' => __('Add Tags'),
                    'remove' => __('Remove Tags'),
                ],
                'default' => 'add',
            ],
            [
                'id' => 'locality',
                'label' => __('Tag Locality'),
                'type' => 'select',
                'options' => [
                    'local' => __('Local'),
                    'global' => __('Global'),
                    'any' => __('Any'),
                ],
                'default' => 'local',
            ],
            [
                'id' => 'tags',
                'label' => __('Tags'),
                'type' => 'picker',
                'multiple' => true,
                'options' => $tags,
                'placeholder' => __('Pick a tag'),
            ],
            [
                'id' => 'relationship_type',
                'label' => __('Relationship Type'),
                'type' => 'input',
                'display_on' => [
                    'action' => 'add',
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

        if ($this->filtersEnabled($node)) {
            $filters = $this->getFilters($node);
            $extracted = $this->extractData($rData, $filters['selector']);
            if ($extracted === false) {
                return false;
            }
            $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
        } else {
            $matchingItems = $rData;
            if ($params['scope']['value'] == 'attribute') {
                $matchingItems = Hash::extract($matchingItems, 'Event._AttributeFlattened.{n}');
            }
        }
        $result = false;
        $options = [
            'tags' => $params['tags']['value'],
            'local' => $params['locality']['value'] == 'any' ? null : ($params['locality']['value'] == 'local' ? true : false),
            'relationship_type' => $params['relationship_type']['value'],
        ];
        if ($params['scope']['value'] == 'event') {
            if ($params['action']['value'] == 'remove') {
                $result = $this->__removeTagsFromEvent($matchingItems, $options);
            } else {
                $result = $this->__addTagsToEvent($matchingItems, $options, $user);
            }
        } else {
            if ($params['action']['value'] == 'remove') {
                $result = $this->__removeTagsFromAttributes($matchingItems, $options);
            } else {
                $result = $this->__addTagsToAttributes($matchingItems, $options, $user);
            }
        }
        return $result;
    }

    protected function __addTagsToAttributes(array $attributes, array $options, array $user): bool
    {
        $success = false;
        foreach ($attributes as $attribute) {
            $saveSuccess = $this->Attribute->attachTagsFromAttributeAndTouch($attribute['id'], $attribute['event_id'], $options, $user);
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }
    
    protected function __removeTagsFromAttributes(array $attributes, array $options): bool
    {
        $success = false;
        foreach ($attributes as $attribute) {
            $saveSuccess = $this->Attribute->detachTagsFromAttributeAndTouch($attribute['id'], $attribute['event_id'], $options);
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }

    protected function __addTagsToEvent(array $event, array $options, array $user): bool
    {
        return !empty($this->Event->attachTagsToEventAndTouch($event['Event']['id'], $options, $user));
    }

    protected function __removeTagsFromEvent(array $event, array $options): bool
    {
        return !empty($this->Event->detachTagsFromEventAndTouch($event['Event']['id'], $options));
    }
}
