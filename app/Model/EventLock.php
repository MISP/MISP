<?php
App::uses('AppModel', 'Model');
class EventLock extends AppModel
{
    public $useTable = 'event_locks';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $belongsTo = array(
            'User' => array(
                'className' => 'User',
                'foreignKey' => 'user_id',
            )
    );


    public $validate = array(
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

    public function insertLock($user, $eventId)
    {
        $date = new DateTime();
        $lock = array(
            'timestamp' => $date->getTimestamp(),
            'user_id' => $user['id'],
            'event_id' => $eventId
        );
        $this->deleteAll(array('user_id' => $user['id']));
        $this->create();
        return $this->save($lock);
    }

    public function checkLock($user, $eventId)
    {
        $this->cleanupLock($user, $eventId);
        $locks = $this->find('all', array(
            'recursive' => -1,
            'contain' => array('User.email', 'User.org_id', 'User.id'),
            'conditions' => array(
                'event_id' => $eventId
            )
        ));
        return $locks;
    }

    // If a lock has been active for 15 minutes, delete it
    public function cleanupLock()
    {
        $date = new DateTime();
        $timestamp = $date->getTimestamp();
        $timestamp -= 900;
        $this->deleteAll(array('timestamp <' => $timestamp));
        return true;
    }
}
