<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
class Note extends AnalystData
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
            'AnalystData'
    );

    public $current_type = 'Note';

    public $validate = array(
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }
}
