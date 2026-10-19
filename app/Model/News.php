<?php
App::uses('AppModel', 'Model');

class News extends AppModel
{
    public $actsAs = array('AuditLog', 'Containable');

    public $validate = array(
        'message' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'title' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        )
    );

    public $belongsTo = 'User';

    /**
     * @return false|string
     */
    public function latestNewsTimestamp()
    {
        $data = $this->find('first', [
            'order' => 'date_created DESC',
            'fields' => ['date_created'],
        ]);
        if (!$data) {
            return false;
        }
        return $data['News']['date_created'];
    }

    /**
     * @param array $user
     * @return int News created since the user last read them
     */
    public function unreadCount(array $user)
    {
        return (int)$this->find('count', [
            'conditions' => ['News.date_created >' => (int)$user['newsread']],
            'recursive' => -1,
        ]);
    }
}
