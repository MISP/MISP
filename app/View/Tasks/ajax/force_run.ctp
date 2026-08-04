<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'model' => 'Task',
        'description' => __('Execute the task immediately. This will override the current scheduled execution time, it can take a few seconds for the scheduler to pick up the task.'),
        'title' => __('Force Run Scheduled Task #%s', h($task['Task']['id'])),
        'fields' => [],
        'submit' => [
            'action' => $this->request->params['action'],
        ]
    ]
]);
