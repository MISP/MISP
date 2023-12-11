<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_enrich_event extends WorkflowBaseActionModule
{
    public $id = 'enrich-event';
    public $name = 'Enrich Event';
    public $version = '0.2';
    public $description = 'Enrich all Attributes contained in the Event with the provided module.';
    public $icon = 'asterisk';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Module;


    public function __construct()
    {
        parent::__construct();
        $this->Module = ClassRegistry::init('Module');
        $modules = $this->Module->getModules('Enrichment');
        $moduleOptions = [];
        if (is_array($modules)) {
            $moduleOptions = array_merge([''], Hash::combine($modules, '{n}.name', '{n}.name'));
        } else {
            $moduleOptions[] = $modules;
        }
        sort($moduleOptions);
        $this->params = [
            [
                'id' => 'modules',
                'label' => 'Modules',
                'type' => 'select',
                'options' => $moduleOptions,
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['modules']['value'])) {
            $errors[] = __('No enrichmnent module selected');
            return false;
        }
        $event_id = $rData['Event']['id'];
        $options = [
            'user' => $roamingData->getUser(),
            'event_id' => $event_id,
            'modules' => [$params['modules']['value']]
        ];
        $filters = $this->getFilters($node);
        $extracted = $this->extractData($rData, $filters['selector']);
        if ($extracted === false) {
            return false;
        }
        $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
        if ($this->filtersEnabled($node) && empty($matchingItems)) {
            return true; // Filters are enabled and no matching items was found
        } else if (!empty($matchingItems)) {
            $extractedUUIDs = $this->extractData($matchingItems, '{n}.uuid');
            if ($extractedUUIDs === false) {
                return false;
            }
            $options['attribute_uuids'] = $extractedUUIDs;
        }

        $this->Event = ClassRegistry::init('Event');
        $result = $this->Event->enrichment($options);
        if ($result === true) {
            $this->push_zmq([
                'Warning' => __('Error while trying to reach enrichment service or no module available'),
                'Attribute added' => 0
            ]);
        } else {
            $this->push_zmq([
                'Enriching event' => $event_id,
                'Attribute added' => $result
            ]);
            $fullEvent = $this->Event->fetchEvent($roamingData->getUser(), [
                'eventid' => $event_id,
                'includeAttachments' => 1
            ]);
            $roamingData->setData($fullEvent[0]);
        }
        return true;
    }
}
