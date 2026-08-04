<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6'
    ],
    [
        'field' => 'value',
        'class' => 'span6',
        'type' => 'editor'
    ],
];

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Create variable to make snippet of markdown re-usable for the users'),
        'model' => 'EventReportTemplateVariable',
        'title' => $edit ? __('Edit Variables') : __('Add New Variables'),
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
