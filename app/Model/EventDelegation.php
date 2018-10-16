<?php
App::uses('AppModel', 'Model');

class EventDelegation extends AppModel
{
    public $actsAs = array('Containable');

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

    public function attachTagToEvent($event_id, $tag_id)
    {
        $existingAssociation = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'tag_id' => $tag_id,
                'event_id' => $event_id
            )
        ));
        if (empty($existingAssociation)) {
            $this->create();
            if (!$this->save(array('event_id' => $event_id, 'tag_id' => $tag_id))) {
                return false;
            }
        }
        return true;
    }

    public function transferEvent($delegation, $user)
    {
        $event = $this->Event->fetchEvent($user, array('eventid' => $delegation['EventDelegation']['event_id']));
        if (empty($event)) {
            throw new MethodNotFoundException('Invalid event.');
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
