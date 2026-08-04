<?php
App::uses('AppModel', 'Model');

class ThreatLevel extends AppModel
{
    public $validate = array(
        'name' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
                'required' => true
            ),
        ),
        'description' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'form_description' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
                'required' => true
            ),
        ),
    );

    public function listThreatLevels()
    {
        return $this->find('list', [
            'fields' => ['id', 'name'],
        ]);
    }
}
