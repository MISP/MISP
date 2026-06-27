<?php
App::uses('AppModel', 'Model');

/**
 * Multiple sharing groups (#10818).
 *
 * Join between an event and the *additional* sharing groups it is shared
 * with, on top of the event's own primary distribution / sharing_group_id.
 * Membership in any of these sharing groups grants read access to the
 * event. Purely additive: it never removes access the event already had.
 *
 * @property Event $Event
 * @property SharingGroup $SharingGroup
 */
class EventSharingGroup extends AppModel
{
    public $actsAs = array('Containable');

    public $belongsTo = array(
        'Event',
        'SharingGroup',
    );

    public $validate = array(
        'event_id' => array(
            'rule' => 'numeric',
            'required' => true,
        ),
        'sharing_group_id' => array(
            'rule' => 'numeric',
            'required' => true,
        ),
    );
}
