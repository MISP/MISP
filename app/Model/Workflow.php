<?php
App::uses('AppModel', 'Model');
class Workflow extends AppModel
{
    public $recursive = -1;

    public $actsAs = [
        'AuditLog',
        'Containable',
    ];

    public $belongsTo = [
        'User' => [
            'className' => 'User',
            'foreignKey' => 'user_id',
        ],
        'Organisation' => [
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        ]
    ];

    public $validate = array(
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

    public function getModules(): array
    {
        return [];
    }
}