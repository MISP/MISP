<?php
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'data' => [
        'title' => __('Debug toggle field'),
        'model' => 'Workflow',
        'skip_side_menu' => 1,
        'fields' => [
        ],
        'submit' => [
            'action' => $this->request->params['action'],
        ]
    ]
]);
