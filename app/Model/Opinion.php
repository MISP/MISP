<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
class Opinion extends AnalystData
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
            'AnalystData'
    );

    public $current_type = 'Opinion';
    public $current_type_id = 1;

    public $validate = array(
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }
}
