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
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Create a push/pull org filter rule based on the organisations contained in a blueprint. The selected blueprint\'s rules will be transposed as either a push or a pull rule\'s OR or NOT list as per the selection.'),
        'model' => 'SharingGroupBlueprint',
        'title' => __('Create sync rules'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action']
        ]
    ]
]);
?>
