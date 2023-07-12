<?php
include_once APP . 'Model/WorkflowModules/action/Module_tag_operation.php';

class Module_assign_country_from_enrichment extends Module_tag_operation
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'assign_country';
    public $name = 'Assign country';
    public $description = 'Add or remove country Galaxy Cluster based on provided data';
    public $icon = 'globe';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Galaxy;
    private $countryClusters;


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
                ],
                'default' => 'event',
            ],
            [
                'id' => 'hash_path',
                'label' => 'Country Hash path',
                'type' => 'input',
                'placeholder' => 'enrichment.{n}.{n}.values.0',
                'default' => 'enrichment.{n}.{n}.values.0'
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
                'id' => 'galaxy_name',
                'label' => __('Galaxy Name'),
                'type' => 'select',
                'options' => [
                    'country' => 'country',
                ],
                'placeholder' => __('Pick a galaxy name'),
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

        $this->Galaxy = ClassRegistry::init('Galaxy');
        $this->countryClusters = $this->_fetchCountryGalaxyClusters();
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        $params = $this->getParamsWithValues($node);

        $rData = $roamingData->getData();
        $user = $roamingData->getUser();

        $countryExtractionPath = $params['hash_path']['value'];
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
                if (substr($countryExtractionPath, 0, 4) !== '{n}.') {
                    $countryExtractionPath = '{n}.' . $countryExtractionPath;
                }
            }
        }

        $result = false;
        $extractedCountries = Hash::extract($matchingItems, $countryExtractionPath);
        $guessedCountryTags = $this->guessTagFromPath($extractedCountries);
        $options = [
            'tags' => $guessedCountryTags,
            'local' => ($params['locality']['value'] == 'local' ? true : false),
            'relationship_type' => $params['relationship_type']['value'],
        ];
        if ($params['scope']['value'] == 'event') {
            $result = $this->__addTagsToEvent($matchingItems, $options, $user);
        } else {
            $result = $this->__addTagsToAttributes($matchingItems, $options, $user);
        }
        return $result;
    }

    protected function _fetchCountryGalaxyClusters(): array
    {
        $clusters = $this->Galaxy->find('first', [
            'recursive' => -1,
            'conditions' => [
                'name' => 'Country',
            ],
            'contain' => [
                'GalaxyCluster' => ['fields' => ['id', 'uuid', 'value', 'tag_name']],
            ],
        ]);
        return $clusters['GalaxyCluster'];
    }

    protected function guessTagFromPath($countries)
    {
        $matchingTags = [];
        foreach ($countries as $country) {
            foreach ($this->countryClusters as $countryCluster) {
                if (strtolower($countryCluster['value']) == strtolower($country)) {
                    $matchingTags[] = $countryCluster['tag_name'];
                }
            }
        }
        return $matchingTags;
    }
}
