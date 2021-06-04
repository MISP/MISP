<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6'
    ],
    [
        'field' => 'url',
        'class' => 'span6'
    ],
    [
        'field' => 'authkey',
        'class' => 'span6'
    ],
    [
        'field' => 'org_id',
        'label' => 'Owner Organisation',
        'type' => 'select',
        'options' => $dropdownData['org_id'],
        'class' => 'span6',
        'searchable' => 1
    ],
    [
        'field' => 'description',
        'type' => 'textarea',
        'class' => 'input span6'
    ],
    [
        'field' => 'pull_orgs',
        'label' => __('Pull Organisations'),
        'type' => 'checkbox',
    ],
    [
        'field' => 'pull_sharing_groups',
        'label' => __('Pull Sharing Groups'),
        'type' => 'checkbox',
    ]
];
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => false,
        'title' => $edit ? __('Edit Cerebrate connection') : __('Add Cerebrate connection'),
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
?>
