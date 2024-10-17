<?php
$fields = [
    [
        'field' => 'collection_id',
        'class' => 'input span6',
        'options' => $dropdownData['collections'],
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
            //'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);

