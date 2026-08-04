<?php

App::uses('AppModel', 'Model');


class EventReportTemplateVariable extends AppModel
{
    public $useTable = 'event_report_template_variables';

    public $displayField = 'name';

    public $validate = [
        'name' => [
            'valueNotEmpty' => [
                'rule' => ['valueNotEmpty'],
            ],
            'unique' => [
                'rule' => 'isUnique',
                'message' => 'A similar name already exists.',
            ],
        ]
    ];

    public function getAll(): array
    {
        $allVars = $this->find('all');
        return Hash::extract($allVars, '{n}.EventReportTemplateVariable');
    }
}
