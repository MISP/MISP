<?php
require_once 'OrgsContributorsGeneric.php';

class OrgsUsingObjectsWidget extends OrgsContributorsGeneric
{
    public $title = 'Orgs using MISP objects';
    public $description = 'Display the logos of all organisations having shared at least one event containing an object in the last 100 days';

    protected function filter($user, $org, $start_timestamp) {
        $options['joins'] = array(
                array('table' => 'objects',
                        'alias' => 'Objects',
                        'type' => 'INNER',
                        'conditions' => array(
                                'Objects.event_id = Event.id',
                        )
                )
        );
        $options['fields'] = 'Event.id';
        $options['limit'] = 1;
        $conditions = $this->Event->createEventConditions($user);
        $conditions['AND'][] = array('Event.orgc_id' => $org['Organisation']['id'], 'Event.timestamp >' => $start_timestamp);
        $options['conditions'] = $conditions;
        $eventsIds = $this->Event->find('all', $options);
        return count($eventsIds) > 0;
    }
}
