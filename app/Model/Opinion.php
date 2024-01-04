<?php
App::uses('AppModel', 'Model');
class Opinion extends AppModel
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
            'AnalystData'
    );

    public $current_type = 'Opinion';

    public $validate = array(
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }
}
