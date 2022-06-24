<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6',
        'placeholder' => 'Name of the workflow blueprint',
    ],
    [
        'field' => 'description',
        'type' => 'textarea',
        'class' => 'input span6',
        'placeholder' => 'Concise description of the workflow blueprint',
    ],
    [
        'field' => 'data',
        'type' => 'textarea',
        'class' => 'input span6',
        'div' => (!empty($fromEditor) ? 'hidden' : '')
    ]
];
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => false,
        'model' => 'WorkflowBlueprint',
        'title' => $edit ? __('Edit Workflow Blueprint') : __('Add Workflow Blueprint'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);

if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
