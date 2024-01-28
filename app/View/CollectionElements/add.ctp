<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'element_uuid',
        'class' => 'input span6',
        'onChange' => 'alert(1);'
    ],
    [
        'field' => 'element_type',
        'class' => 'input span6',
        'options' => $dropdownData['types'],
        'type' => 'dropdown'
    ],
    [
        'field' => 'description',
        'class' => 'span6',
        'type' => 'textarea'
    ]
];

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => null,
        'model' => 'CollectionElement',
        'title' => __('Add element to Collection'),
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
