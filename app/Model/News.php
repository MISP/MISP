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
            'order' => 'News.date_created DESC',
            'fields' => ['date_created'],
        ]);
        if (!$data) {
            return false;
        }
        return $data['News']['date_created'];
    }
}
