<?php
App::uses('AppModel', 'Model');
class NoticelistEntry extends AppModel
{
    public $useTable = 'noticelist_entries';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'value' => array(
            'rule' => array('valueNotEmpty'),
        )
    );

    public $belongsTo = array(
            'Noticelist' => array(
                'className' => 'Noticelist',
                'foreignKey' => 'noticelist_id',
                'counterCache' => true
            )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        $this->data['NoticelistEntry']['data'] = json_encode($this->data['NoticelistEntry']['data']);
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $key => $val) {
            if (!empty($results[$key]['NoticelistEntry']['data'])) {
                $results[$key]['NoticelistEntry']['data'] = json_decode($results[$key]['NoticelistEntry']['data'], true);
            }
        }
        return $results;
    }
}
