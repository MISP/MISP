<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_tag_operation extends WorkflowBaseActionModule
{
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
        $this->Attribute = ClassRegistry::init('Attribute');
        $tags = $this->Tag->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => ['name asc'],
            'fields' => ['Tag.id', 'Tag.name']
        ]);
        $tags = array_column(array_column($tags, 'Tag'), 'name', 'id');
        $this->params = [
            [
                'id' => 'scope',
                'label' => 'Scope',
                'type' => 'select',
                'options' => [
                    'event' => __('Event'),
                    'attribute' => __('Attributes'),
                ],
                'default' => 'event',
            ],
            [
                'id' => 'action',
                'label' => 'Action',
                'type' => 'select',
                'options' => [
                    'add' => __('Add Tags'),
                    'remove' => __('Remove Tags'),
                ],
                'default' => 'add',
            ],
            [
                'id' => 'tags',
                'label' => 'Tags',
                'type' => 'picker',
                'multiple' => true,
                'options' => $tags,
                'placeholder' => __('Pick a tag'),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);

        $rData = $roamingData->getData();

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
                $matchingItems = Hash::extract($matchingItems, '_AttributeFlattened.{n}');
            }
        }
        $result = false;
        if ($params['scope']['value'] == 'event') {
            if ($params['action']['value'] == 'remove') {
                $result = $this->__removeTagsFromEvent($matchingItems, $params['tags']['value']);
            } else {
                $result = $this->__addTagsToEvent($matchingItems, $params['tags']['value']);
            }
        } else {
            if ($params['action']['value'] == 'remove') {
                $result = $this->__removeTagsFromAttributes($matchingItems, $params['tags']['value']);
            } else {
                $result = $this->__addTagsToAttributes($matchingItems, $params['tags']['value']);
            }
        }
        return $result;
    }

    private function __addTagsToAttributes(array $attributes, array $tags): bool
    {
        $success = false;
        foreach ($attributes as $attribute) {
            $saveSuccess = $this->Attribute->attachTagsFromAttributeAndTouch($attribute['id'], $attribute['event_id'], $tags);
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }
    
    private function __removeTagsFromAttributes(array $attributes,array  $tags): bool
    {
        $success = false;
        foreach ($attributes as $attribute) {
            $saveSuccess = $this->Attribute->detachTagsFromAttributeAndTouch($attribute['id'], $attribute['event_id'], $tags);
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }

    private function __addTagsToEvent(array $event, array $tags): bool
    {
        return !empty($this->Event->attachTagsToEventAndTouch($event['Event']['id'], $tags));
    }

    private function __removeTagsFromEvent(array $event, array $tags): bool
    {
        return !empty($this->Event->detachTagsFromEventAndTouch($event['Event']['id'], $tags));
    }
}
