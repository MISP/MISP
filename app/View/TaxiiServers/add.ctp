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
        'field' => 'discovery_url',
        'class' => 'span6'
    ],
    [
        'field' => 'skip_proxy',
        'label' => 'Skip Proxy (if applicable)',
        'type' => 'checkbox',
        'default' => false
    ],
    [
        'field' => 'enabled',
        'label' => __('Enabled'),
        'type' => 'checkbox',
        'default' => !$edit
    ],
    [
        'field' => 'auth_type',
        'label' => 'Authentication Type',
        'type' => 'select',
        'options' => ['basic' => 'Basic', 'bearer' => 'Bearer'],
        'default' => 'basic',
        'class' => 'span6'
    ],
    [
        'field' => 'username',
        'label' => 'Username',
        'type' => 'text auth-basic-field',
        'class' => 'input span6 auth-basic-field'
    ],
    [
        'field' => 'password',
        'label' => 'Password',
        'type' => 'password auth-basic-field',
        'class' => 'input span6 auth-basic-field'
    ],
    [
        'field' => 'api_key',
        'label' => 'Bearer Token',
        'type' => 'text auth-bearer-field',
        'class' => 'input span6 auth-bearer-field'
    ],
    [
        'field' => 'api_root',
        'class' => 'span6',
        'type' => 'dropdown',
        'options' => [],
        'populateAction' => json_encode([
            'uri' => '/taxii_servers/getRoot',
            'body' => [
                'discovery_url' => '{{#TaxiiServerDiscoveryUrl}}',
                'auth_type' => '{{#TaxiiServerAuthType}}',
                'username' => '{{#TaxiiServerUsername}}',
                'password' => '{{#TaxiiServerPassword}}',
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
                'auth_type' => '{{#TaxiiServerAuthType}}',
                'username' => '{{#TaxiiServerUsername}}',
                'password' => '{{#TaxiiServerPassword}}',
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
?>
<script>
$(document).ready(function() {
    $('#TaxiiServerAuthType').trigger('change');
});
</script>
<?php
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
