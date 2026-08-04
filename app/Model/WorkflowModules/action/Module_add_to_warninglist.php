<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_add_to_warninglist extends WorkflowBaseActionModule 
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'add_to_warninglist';
    public $name = 'Add to warninglist';
    public $description = 'Append attributes to an active custom warninglist.';
    public $icon = 'exclamation-triangle';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    /** @var Warninglist */
    private $Warninglist;
    /** @var WarninglistEntry */
    private $WarninglistEntry;
    private $warninglists;


    public function __construct()
    {
        parent::__construct();
        $this->Warninglist = ClassRegistry::init('Warninglist');
        $this->warninglists = $this->Warninglist->find('all', [
            'fields' => ['id', 'name', 'enabled', 'version', 'description', 'type'],
            'recursive' => -1,
            'conditions' => ['default' => 0, 'enabled' => 1],
        ]);

        $moduleOptions = Hash::combine($this->warninglists, '{n}.Warninglist.id', '{n}.Warninglist.name');
        $this->params = [
            [
                'id' => 'warninglist',
                'label' => __('Warninglist'),
                'type' => 'picker',
                'options' => $moduleOptions,
                'placeholder' => __('No warninglist selected'),
                'picker_options' => [
                    'placeholder_text' => !empty($this->warninglists) ? __('Pick an active custom warninglist') : __('No active custom warninglist available'),
                ],
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);

        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['warninglist']['value'])) {
            $errors[] = __('No warninglist selected');
            return false;
        }

        $matchingItems = $this->getMatchingItemsForAttributes($node, $rData);
        if ($matchingItems === false) {
            return true;
        }
        
        $selectedWarninglist = $params['warninglist']['value'];

        $warninglist = array_values(array_filter($this->warninglists, function($wl) use ($selectedWarninglist) {
            return $wl['Warninglist']['id'] == $selectedWarninglist;
        }))[0]['Warninglist'];
        
        $this->WarninglistEntry = ClassRegistry::init('WarninglistEntry');
        $entries = $this->WarninglistEntry->find('column', [
            'conditions' => ['warninglist_id' => $warninglist['id']],
            'fields' => ['WarninglistEntry.value'],
        ]);
       
        foreach($matchingItems as $attribute) {
            if(!in_array($attribute['value'], $entries)) {
                $entries[] = $attribute['value'];
            }

        }
        $warninglist += array('list' => $entries);
        $id = $this->Warninglist->import($warninglist);
        
        if($id && $id>0) {
            return true;
        } else {
            return false;
        }
    }

}
