<?php
// Header section
$headerTitle = __('Roles');
$headerDescription = __('Instance specific permission roles.');

$headerActions = [];
if ($isSiteAdmin) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add role'),
        'icon' => 'plus',
        'url' => $baseurl . '/admin/roles/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$fields = [];


$fields[] = [
    'element' => 'checkbox',
    'data_path' => 'Role.id',
    'card_section' => 'selector',
];

$fields[] = [
    'name' => __('ID'),
    'sort' => 'Role.id',
    'data_path' => 'Role.id',
    'element' => 'id',
    'url' => $baseurl . '/roles/view/%id%',
];

$fields[] = [
    'name' => __('Default'),
    'sort' => 'Role.default',
    'data_path' => 'Role.default',
    'element' => 'default',
];

$fields[] = [
    'name' => __('Name'),
    'sort' => 'Role.name',
    'data_path' => 'Role',
    'element' => 'role',
];

$fields[] = [
    'name' => __('Permission'),
    'sort' => 'Role.permission',
    'element' => 'custom',
    'function' => function (array $row) use ($options) {
        return h($options[$row['Role']['permission']] ?? $row['Role']['permission']);
    },
];

$fields[] = [
    'name' => __('Permissions'),
    'data_path' => 'Role',
    'element' => 'role_permissions',
    'permFlags' => $permFlags,
    'isAdmin' => $isAdmin,
];

$fields[] = [
    'name' => __('Memory Limit'),
    'sort' => 'Role.memory_limit',
    'requirement' => $isAdmin,
    'element' => 'custom',
    'function' => function (array $row) use ($default_memory_limit) {
        $value = $row['Role']['memory_limit'];
        return empty($value) ? h($default_memory_limit) : h($value);
    },
];

$fields[] = [
    'name' => __('Max execution time'),
    'sort' => 'Role.max_execution_time',
    'requirement' => $isAdmin,
    'element' => 'custom',
    'function' => function (array $row) use ($default_max_execution_time) {
        $value = $row['Role']['max_execution_time'];
        return (empty($value) ? h($default_max_execution_time) : h($value)) . '&nbsp;s';
    },
];

$fields[] = [
    'name' => __('Searches / 15 mins'),
    'sort' => 'Role.rate_limit_count',
    'requirement' => $isAdmin,
    'element' => 'custom',
    'function' => function (array $row) {
        $value = $row['Role']['rate_limit_count'];
        if (empty($row['Role']['enforce_rate_limit']) || empty($value)) {
            return __('Unlimited');
        }
        return h($value);
    },
];

$fields[] = [
    'name' => __('Max result by restSearch'),
    'header_title' => __('Maximum number of attributes returned by restSearch calls. For Objects and Events, this limit is divided by 3 and 10 respectively. If undefined, the server default is used.'),
    'sort' => 'Role.restsearch_limit_result',
    'requirement' => $isAdmin,
    'element' => 'custom',
    'function' => function (array $row) {
        $default = (int) Configure::read('MISP.default_restsearch_limit');
        $value = $row['Role']['restsearch_limit_result'];
        if (is_null($value) && empty($row['Role']['perm_site_admin'])) {
            if ($default == 0) {
                return __('Undefined - Fallback to <strong>Server Default (Unlimited)</strong>');
            }
            return __('Undefined - Fallback to <strong>Server Default (%s)</strong>', h($default));
        } else if (is_null($value) && !empty($row['Role']['perm_site_admin'])) {
            return __('Undefined - Fallback to <strong>Unlimited as Site Admin</strong>');
        }
        return (empty($value) ? __('Unlimited') : h($value));
    },
];

$fields[] = [
    'name' => __('Actions'),
    'element' => 'row_actions',
    'data_path' => 'Role.id',
    'actions' => array_values(array_filter([
        [
            'type' => 'navigate',
            'label' => __('View'),
            'icon' => 'eye',
            'url' => $baseurl . '/roles/view/%id%',
        ],
        $isSiteAdmin ? [
            'type' => 'modal',
            'label' => __('Edit'),
            'icon' => 'pen-to-square',
            'url' => $baseurl . '/admin/roles/edit/%id%',
        ] : null,
        $isSiteAdmin ? [
            'type' => 'postLink',
            'label' => __('Set as default'),
            'icon' => 'star',
            'url' => $baseurl . '/admin/roles/set_default/%id%',
            'requirement' => function ($row) {
                return empty($row['Role']['default']);
            },
        ] : null,
        $isSiteAdmin ? [
            'type' => 'modal',
            'label' => __('Delete'),
            'icon' => 'trash',
            'size' => 'sm',
            'url' => $baseurl . '/admin/roles/deleteSelection/%id%',
            'class' => 'text-danger',
        ] : null,
    ])),
];

$scaffoldFilterBar = [
    'pull' => 'right',
    'children' => [
        [
            'type' => 'search',
            'button' => __('Filter'),
            'placeholder' => __('Enter value to search'),
            'name'        => 'name',
            'mode'        => 'quickFilter',
        ],
    ],
];

if ($isSiteAdmin) {
    $scaffoldFilterBar['delete'] = '/deleteSelection';
    $scaffoldFilterBar['delete_url'] = '/admin/roles/deleteSelection';
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => 'Role.id',
            'row_dblclick_url' => $baseurl . '/roles/view/%id%',
            'filter_bar' => $scaffoldFilterBar,
            'fields' => $fields,
        ]
    ],
    'item_url' => '/roles'
]);
