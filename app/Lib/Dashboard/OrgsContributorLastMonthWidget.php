<?php
require_once 'OrgsContributorsGeneric.php';

class OrgsContributorLastMonthWidget extends OrgsContributorsGeneric
{
    public $title = 'Active Contributors in the last 30 days';
    public $description = 'Display the logos of all organisations having shared at least one event in the past month.';

    protected function filter($user, $org, $start_timestamp) {
        $conditions = $this->Event->createEventConditions($user);
        $conditions['AND'][] = array('OR' => array('Event.orgc_id' => $org['Organisation']['id'], 'Event.org_id' => $org['Organisation']['id']));
        $conditions['AND'][] = array('Event.timestamp >=' => $start_timestamp);
        $results = array_values($this->Event->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'limit' => 1,
            'fields' => array('Event.id')
        )));
        return count($results) > 0;
    }
}
