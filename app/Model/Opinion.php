<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
class Opinion extends AnalystData
{

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'Containable',
        'AnalystData',
    );

    public $current_type = 'Opinion';
    public $current_type_id = 1;

    public const EDITABLE_FIELDS = [
        'opinion',
        'comment',
    ];

    public const SEARCHABLE_FIELDS = [
        'comment',
    ];

    const QUERY_FIELDS = [
        'opinion' => ['kind' => 'int', 'column' => 'Opinion.opinion', 'nullable' => 'Opinion.opinion'],
        'comment' => ['kind' => 'string', 'column' => 'Opinion.comment', 'nullable' => 'Opinion.comment'],
    ];

    const REST_SEARCH_ORDER_FIELDS = [
        'Opinion' => ['id', 'created', 'modified', 'distribution', 'opinion'],
    ];

    public $childValidate = [];

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }
}
