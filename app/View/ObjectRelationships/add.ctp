<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6'
    ],
    [
        'field' => 'description',
        'class' => 'span6',
        'type' => 'editor'
    ],
    [
        'field' => 'highlighted',
        'type' => 'checkbox',
    ],
];

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Create Object Relationship'),
        'model' => 'ObjectRelationship',
        'title' => $edit ? __('Edit') : __('Add'),
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
