<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
class Relationship extends AnalystData
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
            'AnalystData'
    );

    public $current_type = 'Relationship';
    public $current_type_id = 2;

    public $validate = array(
    );
}
