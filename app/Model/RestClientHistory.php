<?php
App::uses('AppModel', 'Model');

class RestClientHistory extends AppModel
{
    public $belongsTo = array(
            'Org' => array(
                    'className' => 'Organisation',
                    'foreignKey' => 'org_id',
                    'order' => array(),
                    'fields' => array('id', 'name', 'uuid')
            ),
            'User' => array(
                    'className' => 'User',
                    'foreignKey' => 'user_id',
                    'order' => array(),
                    'fields' => array('id', 'email')
            ),
        );

    public function cleanup($user_id)
    {
        $list = $this->find('list', array(
            'conditions' => array(
                'RestClientHistory.user_id' => $user_id
            ),
            'page' => 1,
            'limit' => 10,
            'order' => array('RestClientHistory.timestamp DESC'),
            'fields' => array('RestClientHistory.id', 'RestClientHistory.timestamp')
        ));
        $this->deleteAll(array(
            'RestClientHistory.user_id' => $user_id,
            'RestClientHistory.bookmark' => 0,
            'NOT' => array(
                'RestClientHistory.id' => array_keys($list)
            )
        ));
    }
}
