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

    public const SEARCHABLE_FIELDS = [
        'note',
    ];

    const QUERY_FIELDS = [
        'note' => ['kind' => 'string', 'column' => 'Note.note', 'nullable' => 'Note.note'],
        'language' => ['kind' => 'string', 'column' => 'Note.language', 'nullable' => 'Note.language'],
    ];

    const REST_SEARCH_ORDER_FIELDS = [
        'Note' => ['id', 'created', 'modified', 'distribution'],
    ];

    public $childValidate = [];

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }
}
