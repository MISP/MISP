<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6',
    ],
    [
        'field' => 'description',
        'type' => 'textarea',
        'class' => 'input span6',
    ],
    [
        'field' => 'data',
        'type' => 'textarea',
        'class' => 'input span6'
    ]
];
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => false,
        'model' => 'Workflow',
        'title' => $edit ? __('Edit Workflow') : __('Add Workflow'),
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
