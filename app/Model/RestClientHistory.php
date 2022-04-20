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

    /**
     * @param array $user
     * @param array $history
     * @return void
     * @throws Exception
     */
    public function insert(array $user, array $history)
    {
        $history['org_id'] = $user['org_id'];
        $history['user_id'] = $user['id'];

        $this->create();
        $this->save($history, ['atomic' => false]);
        $this->cleanup($user['id']);
    }

    public function cleanup($user_id)
    {
        $keepIds = $this->find('column', array(
            'conditions' => array(
                'RestClientHistory.user_id' => $user_id
            ),
            'page' => 1,
            'limit' => 10,
            'order' => array('RestClientHistory.timestamp DESC'),
            'fields' => array('RestClientHistory.id')
        ));
        $this->deleteAll(array(
            'RestClientHistory.user_id' => $user_id,
            'RestClientHistory.bookmark' => 0,
            'NOT' => array(
                'RestClientHistory.id' => $keepIds
            )
        ), false);
    }
}
