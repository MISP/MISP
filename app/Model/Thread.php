<?php

App::uses('AppModel', 'Model');

class Thread extends AppModel
{
    public $actsAs = array(
            'Containable',
            'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
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
}
