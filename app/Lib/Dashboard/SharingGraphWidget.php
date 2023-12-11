<?php
/**
* Sharing Graph widget which computes a sharing score for each local organizations
* The score is computed for each month.
*
* Warning: the scoring function is very experimental. Tweak it as you wish.
*/
class SharingGraphWidget
{
    public $title = 'Sharing Trends';
    public $render = 'MultiLineChart';
    public $width = 8;
    public $height = 6;
    public $description = 'A graph to show sharing trends per organisation';
    public $cacheLifetime = 10;
    public $autoRefreshDelay = false;
    public $params = array (
        'blocklist_orgs' => 'A list of organisation names to filter out',
        'months' => 'Number of past months to consider for the graph'
    );

    public $placeholder =
'{
    "blocklist_orgs": ["Orgs to filter"],
    "months": "6"
}';


    private function attribute_scoring($attribute) {
        // each attribute gets 1 point
        return 1;
    }

    private function object_scoring($object) {
        $score = 0;
        $this->Object->bindModel(array('hasMany' => array('ObjectReference' => array('foreignKey' => 'object_id'))));
        $o = $this->Object->find('first', array('conditions' => array('id' => $object['id'])));
        // We score for each object reference from this object
        foreach ($o['ObjectReference'] as $reference ) {
            //TODO more points for different types of references ?
            $score += 2;
        }
        return $score+50; // bonus for having an object
    }

    private function event_scoring($event) {
        $score = 0;
        $attr_count = 0;
        // Simple attribute scoring
        foreach($event['Attribute'] as $attribute) {
            $attr_count++;
            $score += $this->attribute_scoring($attribute);
            // cap at 100 attributes max per event to avoid privileging large dump
            if ($attr_count > 100)
                break;
        }
        //Object scoring
        foreach($event['Object'] as $object) {
            $score += $this->object_scoring($object);
        }
        // Todo check use of taxonomies, tagging for extra points
        return $score;
    }

    /*
    * Target_month must be from 1 to 12
    * Target year must be 4 digits
    */
    private function org_scoring($user, $org, $target_month, $target_year) {
        $total_score = 0;

        $start_date = $target_year.'-'.$target_month.'-01';
        if($target_month == 12) {
            $end_date = ($target_year+1).'-01-01';
        } else {
            $end_date = $target_year.'-'.($target_month+1).'-01';
        }
        $conditions = array('Event.orgc_id' => $org['Organisation']['id'], 'Event.date >=' => $start_date, 'Event.date <' => $end_date);

        //This is required to enforce the ACL (not pull directly from the DB)
        $eventIds = $this->Event->fetchSimpleEventIds($user, array('conditions' => $conditions));

        if(!empty($eventIds)) {
            $params = array('Event.id' => $eventIds);
            $events = $this->Event->find('all', array('conditions' => array('AND' => $params)));
            foreach($events as $event) {
                $total_score+= $this->event_scoring($event);
            }
        }
        return $total_score;
    }

    private function filter_ghost_orgs(&$data, $orgs){
        foreach ($data['data'] as &$item) {
            foreach(array_keys($orgs) as $org_name) {
                unset($item[$org_name]);
            }
        }
    }

    public function handler($user, $options = array())
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Org = ClassRegistry::init('Organisation');
        $this->Event = ClassRegistry::init('Event');
        $this->Attribute = ClassRegistry::init('Attribute');
        $this->Object = ClassRegistry::init('Object');
        $this->ObjectReference = ClassRegistry::init('ObjectReference');
        $orgs = $this->Org->find('all', array( 'conditions' => array('Organisation.local' => 1)));
        $current_month = date('n');
        $current_year = date('Y');
        $limit = 6; // months
        if(!empty($options['months'])) {
            $limit = (int) ($options['months']);
        }
        $offset = 0;
        $ghost_orgs = array(); // track orgs without any contribution
        // We start by putting all orgs_id in there:
        foreach($orgs as $org) {
            // We check for blocklisted orgs
            if(!empty($options['blocklist_orgs']) && in_array($org['Organisation']['name'], $options['blocklist_orgs'])) {
                unset($orgs[$offset]);
            } else {
                $ghost_orgs[$org['Organisation']['name']] = true;
            }
            $offset++;
        }
        $data = array();
        $data['data'] = array();
        for ($i=0; $i < $limit; $i++) {
            $target_month = $current_month - $i;
            $target_year = $current_year;
            if ($target_month < 1) {
                $target_month += 12;
                $target_year -= 1;
            }
            $item = array();
            $item ['date'] = $target_year.'-'.$target_month.'-01';
            foreach($orgs as $org) {
                    $score = $this->org_scoring($user, $org, $target_month, $target_year);
                    $item[$org['Organisation']['name']] = (int) round(log($score, 1.1));  // taking the logarithmic view
                    // if a positive score is detected at least once it's enough to be
                    // considered for the graph
                    if($score > 0) {
                        unset($ghost_orgs[$org['Organisation']['name']]);
                    }
                }
            $data['data'][] = $item;
        }
        $this->filter_ghost_orgs($data, $ghost_orgs);
        return $data;
    }
}
