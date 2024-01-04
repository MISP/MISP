<?php
App::uses('AppModel', 'Model');
class Relationship extends AnalystData
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
            'AnalystData'
    );

    public $current_type = 'Relationship';

    public $validate = array(
    );
}
