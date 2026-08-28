<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_attach_decay_score extends WorkflowBaseActionModule
{
    public $version = '0.1';
    public $id = 'attach-decay-score';
    public $name = 'Attach decay score';
    public $description = 'Attach selected decaying model score to Attributes.';
    public $icon = 'chart-line';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Attribute;
    private $DecayingModel;

    public function __construct()
    {
        parent::__construct();
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $this->DecayingModel = ClassRegistry::init('DecayingModel');
        $this->decayingmodels = $this->DecayingModel->find('all', [
            'recursive' => -1,
            'fields' => ['DecayingModel.id', 'DecayingModel.name'],
            'conditions' => array('DecayingModel.enabled' => 1)
        ]);
        $models = array_column(array_column($this->decayingmodels, 'DecayingModel'), 'name', 'id');
        $this->params = [
            [
                'id' => 'decayingmodels',
                'label' => __('Decaying Model'),
                'type' => 'picker',
                'multiple' => 'true',
                'options' => $models,
                'placeholder' => __('Pick a Decaying Model')
            ]
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $user = $roamingData->getUser();

        if (empty($params['decayingmodels']['value'])) {
            	$errors[] = __('No decaying model selected');
            	return false;
        }

        $matchingItems = $this->getMatchingItemsForAttributes($node, $rData);
        if ($matchingItems === false) {
            	return true;
        }
		
        $uuids = array_values(array_unique(array_column($matchingItems, 'uuid')));
        if (empty($uuids)) {
            // An empty uuid filter would be dropped by restSearch and match every
            // attribute on the instance, so bail out the same way the per-attribute
            // loop used to: without touching the data.
            $roamingData->setData($rData);
            return true;
        }

        $filters = [];
        $filters['uuid'] = $uuids;
        $filters['includeDecayScore'] = '1';
        $filters['decayingModel'] = $params['decayingmodels']['value'];
        $rParams = $this->Attribute->restSearch($user, 'json', $filters, true);
        $attributesWithScore = $this->Attribute->fetchAttributes($user, $rParams);
        $attributesWithScoreByUuid = [];
        foreach ($attributesWithScore as $attributeWithScore) {
            $attributesWithScoreByUuid[$attributeWithScore['Attribute']['uuid']] = $attributeWithScore['Attribute'];
        }
        unset($attributesWithScore);

        foreach ($matchingItems as $attribute) {
            if (!empty($attributesWithScoreByUuid[$attribute['uuid']])) {
                $rData = $this->_overrideAttribute($attribute, $attributesWithScoreByUuid[$attribute['uuid']], $rData);
            }
        }
        $roamingData->setData($rData);
        return true;
    }
}
