<?php

App::uses('AppModel', 'Model');

class Thread extends AppModel
{
    public $actsAs = array(
        'AuditLog',
            'Containable',
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'roleModel' => 'Thread',
                    'roleKey' => 'thread_id',
                    'change' => 'full'
            ),
    );
    public $hasMany = 'Post';
    public $belongsTo = array(
        'Event',
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        ),
        'SharingGroup'
    );

    public function updateAfterPostChange($thread, $add = false)
    {
        $count = count($thread['Post']);
        // If we have 0 posts left, delete the thread!
        if ($count == 0) {
            $this->delete($thread['Thread']['id']);
            return false;
        } else {
            $thread['Thread']['post_count'] = $count;
            if ($add) {
                $thread['Thread']['date_modified'] = date('Y/m/d H:i:s');
            }
            $this->save($thread);
            return true;
        }
    }

    // convenience method to check whether a user can see an event
    public function checkIfAuthorised($user, $id)
    {
        if (!isset($user['id'])) {
            throw new MethodNotAllowedException('Invalid user.');
        }
        $this->id = $id;
        if (!$this->exists()) {
            return false;
        }
        $thread = $this->find('first', array(
            'conditions' => array('id' => $id),
            'recursive' => -1
        ));
        if (!empty($thread['Thread']['event_id'])) {
            $event = $this->Event->fetchEvent($user, array(
                'eventid' => $thread['Thread']['event_id'],
                'metadata' => true
            ));
            if (empty($event)) {
                return false;
            }
            $event = $event[0];
            // update the distribution if it diverged from the event
            if (
                $event['Event']['distribution'] != $thread['Thread']['distribution'] ||
                $event['Event']['sharing_group_id'] != $thread['Thread']['sharing_group_id']
            ) {
                $this->Behaviors->unload('SysLogLogable.SysLogLogable');
                $thread['Thread']['distribution'] = $event['Event']['distribution'];
                $thread['Thread']['sharing_group_id'] = $event['Event']['sharing_group_id'];
                $this->save($thread);
            }
            return !empty($event);
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($thread['Thread']['org_id'] == $user['org_id'] || ($thread['Thread']['distribution'] > 0 && $thread['Thread']['distribution'] < 4)) {
            return true;
        }
        if ($thread['Thread']['distribution'] == 4 && $this->SharingGroup->checkIfAuthorised($user, $thread['Thread']['sharing_group_id'])) {
            return true;
        }
        return false;
    }
}
