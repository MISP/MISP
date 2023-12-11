<?php
App::uses('AppModel', 'Model');
class WarninglistType extends AppModel
{
    public $useTable = 'warninglist_types';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'type' => array(
            'rule' => array('valueNotEmpty'),
        )
    );

    public $belongsTo = array(
        'Warninglist'
    );
}
