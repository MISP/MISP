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
        $this->Tag = ClassRegistry::init('Tag');
        $this->Event = ClassRegistry::init('Event');
        $this->Attribute = ClassRegistry::init('MispAttribute');
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
                'picker_options' => [
                    'select_options_url' => '/tags/fastIndex/0.json',
                ],
                'placeholder' => __('Pick a tag'),
            ],
            [
                'id' => 'clusters',
                'label' => __('Galaxy Clusters'),
                'type' => 'picker',
                'multiple' => true,
                'picker_options' => [
                    'select_options_url' => '/tags/fastIndex/1.json',
                ],
                'placeholder' => __('Pick a Galaxy Cluster'),
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
                $result = $this->__removeTagsFromEvent($matchingItems, $options, $roamingData);
            } else {
                $result = $this->__addTagsToEvent($matchingItems, $options, $user, $roamingData);
            }
        } else {
            if ($params['action']['value'] == 'remove') {
                $result = $this->__removeTagsFromAttributes($matchingItems, $options, $roamingData);
            } else {
                $result = $this->__addTagsToAttributes($matchingItems, $options, $user, $roamingData);
            }
        }
        return $result;
    }


    protected function __addTagsToAttributes(array $attributes, array $options, array $user, WorkflowRoamingData $roamingData): bool
    {
        $success = false;
        foreach ($attributes as $attribute) {
            $tagAttached = [];
            $saveSuccess = $this->Attribute->attachTagsToAttributeAndTouch($attribute['id'], $attribute['event_id'], $options, $user, $tagAttached);
            if ($saveSuccess) {
                $tags = $this->genTagObjectsFromTagNames($tagAttached, $options);
                $updatedRData = $this->_addTag($tags, 'attribute', $roamingData->getData(), $attribute);
                $roamingData->setData($updatedRData);
                $this->_buildFastLookupForRoamingData($roamingData->getData());
            }
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }
    
    protected function __removeTagsFromAttributes(array $attributes, array $options, WorkflowRoamingData $roamingData): bool
    {
        $success = false;
        foreach ($attributes as $attribute) {
            $tagDetached = [];
            $saveSuccess = $this->Attribute->detachTagsFromAttributeAndTouch($attribute['id'], $attribute['event_id'], $options, $tagDetached);
            if ($saveSuccess) {
                $tags = $this->genTagObjectsFromTagNames($tagDetached, $options);
                $updatedRData = $this->_removeTag($tags, 'attribute', $roamingData->getData(), $attribute);
                $roamingData->setData($updatedRData);
                $this->_buildFastLookupForRoamingData($roamingData->getData());
            }
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }

    protected function __addTagsToEvent(array $event, array $options, array $user, WorkflowRoamingData $roamingData): bool
    {
        $tagAttached = [];
        $saveSuccess = !empty($this->Event->attachTagsToEventAndTouch($event['Event']['id'], $options, $user, $tagAttached));
        if ($saveSuccess) {
            $tags = $this->genTagObjectsFromTagNames($tagAttached, $options);
            $updatedRData = $this->_addTag($tags, 'event', $roamingData->getData());
            $roamingData->setData($updatedRData);
        }
        return $saveSuccess;
    }

    protected function __removeTagsFromEvent(array $event, array $options, WorkflowRoamingData $roamingData): bool
    {
        $tagDetached = [];
        $saveSuccess = !empty($this->Event->detachTagsFromEventAndTouch($event['Event']['id'], $options, $tagDetached));
        if ($saveSuccess) {
            $tags = $this->genTagObjectsFromTagNames($tagDetached, $options);
            $updatedRData = $this->_removeTag($tags, 'event', $roamingData->getData());
            $roamingData->setData($updatedRData);
        }
        return $saveSuccess;
    }

    private function genTagObjectsFromTagNames($tagNames, $options): array
    {
        return array_map(function ($tagName) use ($options) {
            return [
                'name' => $tagName,
                'relationship_type' => $options['relationship_type'],
                'local' => $options['local'],
            ];
        }, $tagNames);
    }
}
