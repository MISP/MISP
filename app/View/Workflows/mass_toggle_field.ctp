<?php
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'data' => [
        'title' => __('Mass toggle fields'),
        'model' => 'Workflow',
        'skip_side_menu' => 1,
        'fields' => [
            [
                'field' => 'module_ids',
                'required' => 1
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action']
        ]
    ]
]);
