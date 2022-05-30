<?php
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'formOptions' => [
        'enctype' => 'multipart/form-data',
    ],
    'data' => [
        'model' => 'Workflow',
        'title' => __('Import Workflow'),
        'description' => __('Paste a JSON of a Workflow to import or provide a JSON file below.'),
        'fields' => [
            [
                'field' => 'json',
                'type' => 'text',
                'class' => 'input span6',
                'div' => 'input clear',
                'label' => __('JSON'),
                'placeholder' => __('Workflow JSON'),
                'rows' => 18
            ],
            [
                'field' => 'submittedjson',
                'label' => __('JSON file'),
                'type' => 'file',
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
        ]
    ]
]);

echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'workflows', 'menuItem' => 'import'));
