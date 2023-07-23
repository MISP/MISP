<?php
include_once APP . 'Model/WorkflowModules/action/WorkflowBaseActionModule.php';

class Module_add_to_warninglist extends WorkflowBaseActionModule 
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'add_to_warninglist';
    public $name = 'Add to warninglist';
    public $description = 'Add attributes to a custom warninglist';
    public $icon = 'exclamation-triangle';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];


    public function __construct()
    {
        parent::__construct();
        $this->Log = ClassRegistry::init('Log');
        $this->Warninglist = ClassRegistry::init('Warninglist');
        $warninglists = $this->Warninglist->find('all', [
            'fields' => ['id', 'name', 'enabled', 'version', 'description', 'type'],
            'recursive' => -1,
            'conditions' => ['default' => 0, 'enabled' => 1],
        ]);
        $this->warninglists = $warninglists;

        $moduleOptions = array();
        foreach ($warninglists as $item) {
            $moduleOptions[$item['Warninglist']['id']] = $item['Warninglist']['name'];
        }
        $this->params = [
            [
                'id' => 'warninglists',
                'label' => __('Warninglists'),
                'type' => 'select',
                'options' => $moduleOptions
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);

        $params = $this->getParamsWithValues($node);
        $rData = $roamingData->getData();

        $matchingItems = $this->getMatchingItemsForAttributes($node, $rData);
        if ($matchingItems === false) {
            return true;
        }
        
        $selectedWarninglist = $params['warninglists']['value'];
        
        $warninglist = array_values(array_filter($this->warninglists, function($wl) use ($selectedWarninglist) {
            return $wl['Warninglist']['id'] == $selectedWarninglist;
        }))[0]['Warninglist'];
        
        $this->WarninglistEntry = ClassRegistry::init('WarninglistEntry');
        $entries = $this->WarninglistEntry->find('column', array(
            'conditions' => array('warninglist_id' => $warninglist['id']),
            'fields' => array('WarninglistEntry.value')
        ));
       
        foreach($rData['Event']['Attribute'] as $attribute) {
            if(!in_array($attribute['value'], $entries)) {
                array_push($entries, $attribute['value']);
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
