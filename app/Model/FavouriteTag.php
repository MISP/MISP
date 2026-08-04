<?php
App::uses('AppModel', 'Model');

class FavouriteTag extends AppModel
{
    public $actsAs = array('Containable');

    public $validate = array(
        'user_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'tag_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
    );

    public $belongsTo = array('Tag', 'User');
}
