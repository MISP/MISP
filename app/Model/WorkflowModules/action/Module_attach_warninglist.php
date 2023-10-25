<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_attach_warninglist extends WorkflowBaseActionModule
{
    public $version = '0.2';
    public $id = 'attach-warninglist';
    public $name = 'Attach warninglist';
    public $description = 'Attach selected warninglist result.';
    public $icon = 'exclamation-triangle';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    /** @var Warninglist */
    private $Warninglist;
    private $warninglists;


    public function __construct()
    {
        parent::__construct();
        $this->Warninglist = ClassRegistry::init('Warninglist');
        $warninglists = $this->Warninglist->getEnabled();
        $this->warninglists = $warninglists;
        $moduleOptions = array_merge(['ALL' => __('ALL')], Hash::combine($warninglists, '{n}.Warninglist.name', '{n}.Warninglist.name'));
        sort($moduleOptions);
        $this->params = [
            [
                'id' => 'warninglists',
                'label' => __('Warninglists'),
                'type' => 'picker',
                'multiple' => true,
                'options' => $moduleOptions,
                'default' => 'ALL',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['warninglists']['value'])) {
            $errors[] = __('No warninglist module selected');
            return false;
        }

        $matchingItems = $this->getMatchingItemsForAttributes($node, $rData);
        if ($matchingItems === false) {
            return true;
        }

        $warninglists = [];

        if (empty($params['warninglists']['value'])) {
            $errors[] = __('No warninglists selected');
            return false;
        } else if (is_string($params['warninglists']['value'])) {
            $params['warninglists']['value'] = [$params['warninglists']['value']];
        }

        if (in_array('ALL', $params['warninglists']['value'])) {
            $warninglists = $this->warninglists;
        } else {
            $warninglists = array_filter($this->warninglists, function($wl) use ($params) {
                return in_array($wl['Warninglist']['name'], $params['warninglists']['value']);
            });
        }

        $eventWarnings = [];
        foreach ($matchingItems as $attribute) {
            $attributeWithWarning = $this->Warninglist->checkForWarning($attribute, $warninglists);
            if (!empty($attributeWithWarning['warnings'])) {
                foreach ($attributeWithWarning['warnings'] as $warning) {
                    $eventWarnings[$warning['warninglist_id']] = [
                        'id' => $warning['warninglist_id'],
                        'name' => $warning['warninglist_name'],
                        'category' => $warning['warninglist_category'],
                    ];
                }
            }
            $rData = $this->_overrideAttribute($attribute, $attributeWithWarning, $rData);
        }
        $eventWarnings = array_values($eventWarnings);
        $rData['Event']['warnings'] = $eventWarnings;
        $roamingData->setData($rData);
        return true;
    }
}
