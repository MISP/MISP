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
		
        foreach ($matchingItems as $attribute) {
            $filters = [];
            $filters['uuid'] = $attribute['uuid'];
            $filters['includeDecayScore'] = '1';
            $filters['decayingModel'] = $params['decayingmodels']['value'];
            $rParams = $this->Attribute->restSearch($user, 'json', $filters, true);
            $attributeWithScore = $this->Attribute->fetchAttributes($user, $rParams);
            if (!empty($attributeWithScore)) {
                $attributeWithScore = $attributeWithScore[0]['Attribute'];
                $rData = $this->_overrideAttribute($attribute, $attributeWithScore, $rData);
            }
        }
        $roamingData->setData($rData);
        return true;
    }
}
