<?php
App::uses('AppModel', 'Model');

class Task extends AppModel
{
    public $recursive = -1;

    public $useTable = 'scheduled_tasks';

    public $actsAs = array(
        'Containable',
    );

    public $belongsTo = [
        'User',
        'Job' => [
            'className' => 'Job',
            'foreignKey' => 'last_job_id',
        ]
    ];
}
