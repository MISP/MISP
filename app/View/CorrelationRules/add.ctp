<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$this->request->data['CorrelationRule']['selector_list'] = json_encode($this->data['CorrelationRule']['selector_list'], JSON_PRETTY_PRINT);
$fields = [
    [
        'field' => 'name',
        'class' => 'span6'
    ],
    [
        'field' => 'comment',
        'class' => 'span6',
        'type' => 'textarea'
    ],
    [
        'field' => 'selector_type',
        'label' => __('Selector type'),
        'class' => 'input span6',
        'options' => $dropdownData['selector_types'],
        'type' => 'dropdown'
    ],
    [
        'field' => 'selector_list',
        'label' => __('Selector list (json)'),
        'class' => 'span6',
        'type' => 'textarea'
    ]
];

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Create correlation rules to block the creation of correlations between events matching certain criteria. This can be handy when for example a feed\'s daily ingestion is causing heavy over correlation.'),
        'model' => 'CorrelationRule',
        'title' => $edit ? __('Edit Correlation Rule') : __('Add Correlation Rule'),
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
