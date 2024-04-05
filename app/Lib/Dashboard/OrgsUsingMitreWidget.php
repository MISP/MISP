<?php
require_once 'OrgsContributorsGeneric.php';

class OrgsUsingMitreWidget extends OrgsContributorsGeneric
{
    public $title = 'Orgs using MITRE ATT&CK';
    public $description = 'Display the logos of all organisations having shared at least one event using the MITRE ATT&CK tags in the last 100 days';

    protected function filter($user, $org, $start_timestamp) {
        $options['joins'] = array(
                array('table' => 'event_tags',
                        'alias' => 'EventTag',
                        'type' => 'INNER',
                        'conditions' => array(
                                'EventTag.event_id = Event.id',
                        )
                ),
                array('table' => 'tags',
                            'alias' => 'Tag',
                            'type' => 'INNER',
                            'conditions' => array(
                                'Tag.id = EventTag.tag_id'
                            )
                )
        );
        $options['fields'] = 'Event.id';
        $options['limit'] = 1;
        $conditions = $this->Event->createEventConditions($user);
        $conditions['AND'][] = array('Event.orgc_id' =>  $org['Organisation']['id'], 'Event.published' => 1, 'Event.timestamp >=' => $start_timestamp, 'Tag.name LIKE' => 'misp-galaxy:mitre%');
        $options['conditions'] = array('AND' => $conditions);
        $events = $this->Event->find('all', $options);
        return count($events) > 0;
    }
}
