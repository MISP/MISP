<?php

$fields = [
    [
        'key' => __('Id'),
        'path' => 'Role.id'
    ],
    [
        'key' => __('Name'),
        'path' => 'Role.name'
    ],
    [
        'key' => __('Permission level'),
        'path' => 'Role.permission',
        'type' => 'mapping',
        'mapping' => $permissionLevelName
    ]
];
foreach ($permFlags as $permFlag => $permFlagData) {
    $fields[] = [
        'key' => $permFlagData['text'],
        'title' => $permFlagData['title'],
        'path' => 'Role.' . $permFlag,
        'type' => 'boolean',
        'mapping' => [
            false => '<span class="red bold">Denied</span>',
            true => '<span class="green bold">Granted</span>'
        ]
    ];
}
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Role view',
        'data' => $data,
        'fields' => $fields,
        'children' => [
        ]
    ]
);
