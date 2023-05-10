<?php
use Cake\Utility\Inflector;
$fields = [
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'id'
    ],/*
    [
        'name' => __('Default'),
        'data_path' => 'Role.default',
        'element' => 'toggle',
        'url' => '/admin/roles/set_default',
        'url_params_data_paths' => ['Role.id'],
        'checkbox_class' => 'defaultRoleCheckbox',
        'beforeHook' => "$('.defaultRoleCheckbox').prop('checked', false); $(this).prop('checked', true);",
        'requirement' => $isSiteAdmin,
    ],*/
    [
        'name' => __('Default'),
        'data_path' => 'default',
        'element' => 'boolean',
        'colors' => true,
        'requirement' => $isSiteAdmin,
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name'
    ],
    [
        'name' => __('Permission'),
        'sort' => 'permission',
        'element' => 'custom',
        'function' => function (Cake\ORM\Entity $entity) use ($options) {
            return $options[$entity['permission']];
        }
    ]
];

foreach ($permFlags as $k => $permFlag) {
    $fields[] = [
        'name' => $isAdmin ? $permFlag['text'] : Inflector::Humanize(substr($k, 5)),
        'header_title' => $permFlag['title'],
        'sort' =>  $k,
        'data_path' => $k,
        'element' => 'boolean',
        'rotate_header' => $isAdmin,
        'class' => $isAdmin ? 'rotate' : '',
        'colors' => true,
    ];
}

$fields[] = [
    'name' => __('Memory Limit'),
    'sort' => 'memory_limit',
    'data_path' => 'memory_limit',
    'decorator' => function($value) use ($default_memory_limit) {
        return empty($value) ? $default_memory_limit : h($value);
    },
    'requirement' => $isAdmin,
];

$fields[] = [
    'name' => __('Max execution time'),
    'sort' => 'max_execution_time',
    'data_path' => 'max_execution_time',
    'decorator' => function($value) use ($default_max_execution_time) {
        return (empty($value) ? $default_max_execution_time : h($value)) . '&nbsp;s';
    },
    'requirement' => $isAdmin,
];

$fields[] = [
    'name' => __('Searches / 15 mins'),
    'sort' => 'rate_limit_count',
    'data_path' => 'rate_limit_count',
    'decorator' => function($value) {
        return (empty($value) ? __('Unlimited') : h($value));
    },
    'requirement' => $isAdmin,
];

if ($isSiteAdmin) {
    $actions = [
        [
            'open_modal' => '/admin/roles/edit/[onclick_params_data_path]',
            'modal_params_data_path' => 'id',
            'icon' => 'edit',
            'title' => __('Edit role'),
            'requirement' => $loggedUser['Role']['perm_admin']
        ],
        [
            'open_modal' => '/admin/roles/delete/[onclick_params_data_path]',
            'modal_params_data_path' => 'id',
            'icon' => 'trash',
            'title' => __('Delete role'),
            'requirement' => $loggedUser['Role']['perm_admin']
        ]
    ];
} else {
    $actions = [];
}


echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'children' => [
                [
                    'type' => 'simple',
                    'children' => [
                        'data' => [
                            'type' => 'simple',
                            'text' => __('Add role'),
                            'class' => 'btn btn-primary',
                            'popover_url' => '/roles/add',
                            'button' => [
                                'icon' => 'plus',
                            ]
                        ]
                    ]
                ],
                [
                    'type' => 'search',
                    'button' => __('Search'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchKey' => 'value'
                ]
            ]
        ],
        'fields' => $fields,
        'title' => __('Roles Index'),
        'description' => __('Instance specific permission roles.'),
        'pull' => 'right',
        'actions' => $actions
    ]
]);
echo '</div>';
?>
