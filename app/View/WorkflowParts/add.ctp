<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6',
        'placeholder' => 'Name of the workflow part',
    ],
    [
        'field' => 'description',
        'type' => 'textarea',
        'class' => 'input span6',
        'placeholder' => 'Concise description of the workflow part',
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
        'model' => 'WorkflowPart',
        'title' => $edit ? __('Edit Workflow Part') : __('Add Workflow Part'),
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
