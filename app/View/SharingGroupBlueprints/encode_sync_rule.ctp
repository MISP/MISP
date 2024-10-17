<?php
$modelForForm = 'SharingGroupBlueprints';
$fields = [
    [
        'field' => 'type',
        'type' => 'dropdown',
        'options' => ['pull' => 'pull', 'push' => 'push'],
        'class' => 'span6'
    ],
    [
        'field' => 'rule',
        'type' => 'dropdown',
        'options' => ['OR' => 'OR', 'NOT' => 'NOT'],
        'class' => 'span6'
    ],
    [
        'field' => 'server_id',
        'type' => 'dropdown',
        'class' => 'span6',
        'options' => $servers
    ]
];
$description = sprintf(
    '%s<br />%s<br /><br />%s<br />%s',
    __('Create a push or pull rule based '),
    __('Simply create a JSON dictionary using a combination of filters and boolean operators.'),
    '<span class="bold">Filters</span>: org_id, org_type, org_uuid, org_name, org_sector, org_nationality, sharing_group_id, , sharing_group_uuid',
    '<span class="bold">Boolean operators</span>: OR, AND, NOT'
);
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Create a push/pull org filter rule based on the organisations contained in a blueprint. The selected blueprint\'s rules will be transposed as either a push or a pull rule\'s OR or NOT list as per the selection.'),
        'model' => 'SharingGroupBlueprint',
        'title' => __('Create sync rules'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
?>
