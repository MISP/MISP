<?php
App::uses('AppModel', 'Model');

class News extends AppModel
{
    public $actsAs = array('Containable');

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
}
