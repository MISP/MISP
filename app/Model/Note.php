<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
class Note extends AnalystData
{

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'Containable',
        'AnalystData',
    );

    public $current_type = 'Note';
    public $current_type_id = 0;

    public const EDITABLE_FIELDS = [
        'note',
    ];

    public $validate = [];

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }
}
