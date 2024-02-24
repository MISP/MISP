<?php
include_once APP . 'Model/WorkflowModules/action/Module_tag_operation.php';

class Module_tag_replacement_generic extends Module_tag_operation
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'tag_replacement_generic';
    public $name = 'Tag Replacement Generic';
    public $description = 'Attach a tag, or substitue a tag by another';
    public $icon = 'tags';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    public $searchRegex = '';
    public $substitutionTemplate = '';  // Format the template using CakeText::insert where variables are surround by `{{ var }}`


    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'scope',
                'label' => __('Scope'),
                'type' => 'select',
                'options' => [
                    'event' => __('Event'),
                    'attribute' => __('Attributes'),
                    'all' => __('All'),
                ],
                'default' => 'event',
            ],
            [
                'id' => 'remove_substituted',
                'label' => 'Removed substituted tag',
                'type' => 'select',
                'default' => '1',
                'options' => [
                    'no' => __('No'),
                    'yes' => __('Yes'),
                ],
            ],
            [
                'id' => 'locality',
                'label' => __('Tag Locality'),
                'type' => 'select',
                'options' => [
                    'local' => __('Local'),
                    'global' => __('Global'),
                ],
                'default' => 'local',
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
        }

        $matchingEvent = $matchingItems;
        $matchingAttributes = [];
        if ($params['scope']['value'] == 'attribute' || $params['scope']['value'] == 'all') {
            $matchingAttributes = Hash::extract($matchingItems, 'Event._AttributeFlattened.{n}');
        }

        if (empty($matchingItems)) {
            return true;
        }

        $result = false;
        $optionsRemove = [
            'local' => [0, 1],
        ];
        $optionsAdd = [
            'local' => $params['locality']['value'] == 'local' ? true : false,
            'relationship_type' => $params['relationship_type']['value'],
        ];
        if ($params['scope']['value'] == 'event' || $params['scope']['value'] == 'all') {
            $result = $this->replaceOnEvent($matchingEvent, $params, $user, $optionsRemove, $optionsAdd);
        }
        if ($params['scope']['value'] == 'attribute' || $params['scope']['value'] == 'all') {
            $result = $this->replaceOnAttribute($matchingAttributes, $params, $user, $optionsRemove, $optionsAdd);
        }
         return $result;
    }


    protected function replaceOnEvent(array $matchingItems, array $params, array $user, array $optionsRemove, array $optionsAdd): bool
    {
        $result = true;
        $extractedTags = Hash::extract($matchingItems['Event']['Tag'], '{n}.name');
        $options = $this->getReplacementOptions($extractedTags);
        $optionsRemove['tags'] = $options['remove'];
        $optionsAdd['tags'] = $options['add'];
        if ($params['remove_substituted']['value'] == 'yes' && !empty($optionsRemove['tags'])) {
            $result = $this->__removeTagsFromEvent($matchingItems, $optionsRemove);
        }
        if (!empty($optionsAdd['tags'])) {
            $result = $this->__addTagsToEvent($matchingItems, $optionsAdd, $user);
        }
        return $result;
    }

    protected function replaceOnAttribute(array $matchingItems, array $params, array $user, array $optionsRemove, array $optionsAdd): bool
    {
        $result = true;
        foreach ($matchingItems as $attribute) {
            $extractedTags = Hash::extract($attribute['Tag'], '{n}.name');
            $options = $this->getReplacementOptions($extractedTags);
            $optionsRemove['tags'] = $options['remove'];
            $optionsAdd['tags'] = $options['add'];
            if ($params['remove_substituted']['value'] == 'yes' && !empty($optionsRemove['tags'])) {
                $result = $this->__removeTagsFromAttributes([$attribute], $optionsRemove);
            }
            if (!empty($optionsAdd['tags'])) {
                $result = $this->__addTagsToAttributes([$attribute], $optionsAdd, $user);
            }
        }
        return $result;
    }

    protected function isAMatch($matches): bool
    {
        return !empty($matches);
    }

    protected function searchAndReplaceTag(array $tags): array
    {
        $toReturn = [];
        foreach ($tags as $tag) {
            $matches = [];
            preg_match($this->searchRegex, $tag, $matches);
            if ($this->isAMatch($matches)) {
                $toReturn[] = [
                    'matched' => $tag,
                    'substitution' => $this->formatSubstitution($matches),
                ];
            }
        }
        return $toReturn;
    }

    protected function getReplacementOptions(array $extractedTags)
    {
        $substitutionResult = $this->searchAndReplaceTag($extractedTags);
        $tagsToRemove = Hash::extract($substitutionResult, '{n}.matched');
        $tagsToAdd = Hash::extract($substitutionResult, '{n}.substitution');
        return [
            'remove' => $tagsToRemove,
            'add' => $tagsToAdd,
        ];
    }

    protected function formatSubstitution($matches)
    {
        return CakeText::insert($this->substitutionTemplate, $matches, ['before' => '{{', 'after' => '}}']);
    }
}
