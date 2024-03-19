<?php
App::uses('AppModel', 'Model');

class EventDelegation extends AppModel
{
    public $actsAs = array('AuditLog', 'Containable');

    public $validate = array(
        'event_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'org_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        )
    );

    public $belongsTo = array(
        'Event',
        'Org' => array(
            'className' => 'Organisation',
        ),
        'RequesterOrg' => array(
            'className' => 'Organisation'
        ),
        'SharingGroup'
    );

    public function transferEvent($delegation, $user)
    {
        $event = $this->Event->fetchEvent($user, array(
            'eventid' => $delegation['EventDelegation']['event_id'],
            'includeAttachments' => 1
        ));
        if (empty($event)) {
            throw new NotFoundException('Invalid event.');
        }
        $event = $event[0];
        $event['Event']['user_id'] = $user['id'];
        $event['Event']['orgc_id'] = $delegation['EventDelegation']['org_id'];
        $event['Event']['org_id'] = $delegation['EventDelegation']['org_id'];
        $this->Event->delete($delegation['EventDelegation']['event_id']);
        $event_id = $this->Event->savePreparedEvent($event);
        return $event_id;
    }
}
