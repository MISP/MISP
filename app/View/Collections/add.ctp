<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6'
    ],
    [
        'field' => 'type',
        'class' => 'input span6',
        'options' => $dropdownData['types'],
        'type' => 'dropdown'
    ],
    [
        'field' => 'description',
        'class' => 'span6',
        'type' => 'textarea'
    ],
    [
        'field' => 'distribution',
        'class' => 'input',
        'options' => $dropdownData['distributionLevels'],
        'default' => isset($data['Collection']['distribution']) ? $data['Collection']['distribution'] : $initialDistribution,
        'stayInLine' => 1,
        'type' => 'dropdown'
    ],
    [
        'field' => 'sharing_group_id',
        'class' => 'input',
        'options' => $dropdownData['sgs'],
        'label' => __("Sharing Group"),
        'type' => 'dropdown'
    ]
];

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Create collections to organise data shared by the community into buckets based on commonalities or as part of your research process. Collections are first class citizens and adhere to the same sharing rules as for example events do.'),
        'model' => 'Collection',
        'title' => $edit ? __('Edit collection') : __('Add new collection'),
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
