<?php
class OrgsContributorsGeneric
{
    public $render = 'OrgsPictures';
    public $width = 4;
    public $height = 4;
    public $cacheLifetime = 3600;
    public $autoRefreshDelay = false;
    public $params = array (
        'blocklist_orgs' => 'A list of organisation names to filter out',
        'timeframe' => 'Number of days considered for the query (30 by default)'
    );
    public $placeholder =
'{
    "blocklist_orgs": ["Orgs to filter"],
    "timeframe": "30"
}';

    //This is the default filter - to be overriden in children classes
    protected function filter($user, $org, $options) {
        return true;
    }

    public function handler($user, $options = array())
    {
        $this->Org = ClassRegistry::init('Organisation');
        $this->Event = ClassRegistry::init('Event');
        if (!empty($options['timeframe'])) {
            $days = (int) $options['timeframe'];
        } else {
            $days = 30;
        }
        $start_timestamp = $this->Event->resolveTimeDelta($days.'d');

        $orgs = $this->Org->find('all', array( 'conditions' => array('Organisation.local' => 1)));
        $result = array();
        foreach($orgs as $org) {
            if(!empty($options['blocklist_orgs']) && in_array($org['Organisation']['name'], $options['blocklist_orgs'])) {
                continue;
            }
            if ($this->filter($user, $org, $start_timestamp)) {
                $result[] = $org;
            }
        }
        return $result;
    }
}
