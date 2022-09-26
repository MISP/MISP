<?php
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'data' => [
        'title' => __('Execute Workflow'),
        'model' => 'Workflow',
        'skip_side_menu' => 1,
        'fields' => [
            [
                'field' => 'data',
                'type' => 'textarea',
                'class' => 'input span6'
            ]
        ],
        'submit' => [
            'action' => $this->request->params['action'],
        ]
    ]
]);
