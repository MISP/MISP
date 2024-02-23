<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6'
    ],
    [
        'field' => 'owner',
        'class' => 'span6'
    ],
    [
        'field' => 'baseurl',
        'class' => 'span6'
    ],
    [
        'field' => 'api_key',
        'label' => 'API Key',
        'type' => 'text',
        'class' => 'input span6'
    ],
    [
        'field' => 'api_root',
        'class' => 'span6',
        'type' => 'dropdown',
        'options' => [],
        'populateAction' => json_encode([
            'uri' => '/taxii_servers/getRoot',
            'body' => [
                'baseurl' => '{{#TaxiiServerBaseurl}}',
                'api_key' => '{{#TaxiiServerApiKey}}'
            ],
            'type' => 'POST'
        ])
    ],
    [
        'field' => 'collection',
        'class' => 'span6',
        'type' => 'dropdown',
        'options' => [],
        'populateAction' => json_encode([
            'uri' => '/taxii_servers/getCollections',
            'body' => [
                'baseurl' => '{{#TaxiiServerBaseurl}}',
                'api_key' => '{{#TaxiiServerApiKey}}',
                'api_root' => '{{#TaxiiServerApiRoot}}'
            ],
            'type' => 'POST'
        ])
    ],
    [
        'field' => 'description',
        'type' => 'textarea',
        'class' => 'input span6'
    ],
    [
        'field' => 'filters',
        'label' => 'Filter Rules (restsearch JSON)',
        'type' => 'textarea',
        'class' => 'input span6'
    ]
];
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => false,
        'model' => 'TaxiiServer',
        'title' => $edit ? __('Edit TAXII Server connection') : __('Add TAXII Server connection'),
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
