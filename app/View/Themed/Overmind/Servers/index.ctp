<?php
$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Server.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('Explore server'),
                'icon' => 'compass',
                'url' => $baseurl . '/servers/previewIndex/%id%',
            ],
            [
                'type' => 'link',
                'label' => __('Pull all'),
                'icon' => 'arrow-circle-down',
                'url' => $baseurl . '/servers/pull/%id%/full',
                'requirement' => function (array $row) {
                    return !empty($row['Server']['pull']);
                }
            ],
            [
                'type' => 'link',
                'label' => __('Push all'),
                'icon' => 'arrow-circle-up',
                'url' => $baseurl . '/servers/push/%id%/full',
                'requirement' => function (array $row) {
                    return !empty($row['Server']['push']);
                }
            ],
            [
                'type' => 'link',
                'label' => __('Cache instance (last year)'),
                'icon' => 'calendar-days',
                'url' => $baseurl . '/servers/cache/%id%/1y',
                'requirement' => function (array $row) {
                    return !empty($row['Server']['caching_enabled']);
                }
            ],
            [
                'type' => 'link',
                'label' => __('Cache instance'),
                'icon' => 'database',
                'url' => $baseurl . '/servers/cache/%id%',
                'requirement' => function (array $row) {
                    return !empty($row['Server']['caching_enabled']);
                }
            ],
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/servers/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/servers/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $isSiteAdmin
            ]
        ]
    ],
    [
        'name' => __('ID'),
        'sort' => 'Server.id',
        'data_path' => 'Server.id',
        'element' => 'id',
        'url' => $baseurl . '/servers/previewIndex/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Server.name',
        'data_path' => 'Server',
        'element' => 'server_name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    // [
    //     'name' => __('Prio'),
    //     'sort' => 'Server.priority',
    //     'data_path' => 'Server.id',
    //     'element' => 'server_prio',
    //     'display_in' => ['table']
    // ],
    [
        'name' => __('Connection test'),
        'element' => 'server_action_button',
        'button' => [
            'label' => __('Run'),
            'js_action' => 'testConnection',
            'js_param_path' => 'Server.id',
            'cell_id' => 'connection_test_%s',
            'cell_id_param_path' => 'Server.id',
            'result_id' => 'connection_test_result_%s',
            'title' => __('Test remote instance connection')
        ],
        'display_in' => ['table']
    ],
    [
        'name' => __('Sync user'),
        'element' => 'server_action_button',
        'button' => [
            'label' => __('View'),
            'js_action' => 'getRemoteSyncUser',
            'js_param_path' => 'Server.id',
            'cell_id' => 'sync_user_test_%s',
            'cell_id_param_path' => 'Server.id',
            'result_id' => 'sync_user_test_result_%s',
            'title' => __('View remote sync user')
        ],
        'display_in' => ['table']
    ],
    [
        'name' => __('Internal'),
        'sort' => 'Server.internal',
        'data_path' => 'Server.internal',
        'element' => 'server_boolean',
        'true' => __('Internal'),
        'false' => __('Not internal'),
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Push rules'),
        'sort' => 'Server.push',
        'element' => 'server_push_pull',
        'mode' => 'push',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Pull rules'),
        'sort' => 'Server.pull',
        'element' => 'server_push_pull',
        'mode' => 'pull',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Sightings'),
        'sort' => 'Server.push_sightings',
        'data_path' => 'Server.push_sightings',
        'element' => 'server_boolean',
        'true' => __('Enabled'),
        'false' => __('Disabled'),
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Clusters'),
        'sort' => 'Server.push_galaxy_clusters',
        'data_path' => 'Server.push_galaxy_clusters',
        'element' => 'server_boolean',
        'true' => __('Enabled'),
        'false' => __('Disabled'),
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Analyst data'),
        'sort' => 'Server.push_analyst_data',
        'data_path' => 'Server.push_analyst_data',
        'element' => 'server_boolean',
        'true' => __('Enabled'),
        'false' => __('Disabled'),
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Cache'),
        'sort' => 'Server.caching_enabled',
        'data_path' => 'Server',
        'element' => 'server_cache_status',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Organisations'),
        'data_path' => '',
        'element' => 'server_organisations',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Options'),
        'data_path' => 'Server',
        'element' => 'server_options',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Cert files'),
        'data_path' => 'Server',
        'element' => 'server_cert_files',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Bound sync users'),
        'data_path' => 'BoundUsers',
        'element' => 'server_bound_users',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
];

$this->set('headerActions', [
    [
        'type' => 'link',
        'label' => __('List Cerebrates'),
        'icon' => 'globe',
        'url' => $baseurl . '/cerebrates'
    ],
    [
        'type' => 'link',
        'label' => __('List Communities'),
        'icon' => 'users',
        'url' => $baseurl . '/communities'
    ],
    [
        'type' => 'ajax',
        'label' => __('Add Server'),
        'icon' => 'plus',
        'url' => $baseurl . '/servers/add'
    ],
]);

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $servers,
            'primary_id_path' => 'Server.id',
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by server name or URL'),
                        'name' => 'search',
                        'mode' => 'legacy',
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'label' => __('Internal'),
                                'name' => 'internal',
                                'options' => [
                                    '1' => __('Yes'),
                                    '0' => __('No')
                                ]
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Push enabled'),
                                'name' => 'push',
                                'options' => [
                                    '1' => __('Yes'),
                                    '0' => __('No')
                                ]
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Pull enabled'),
                                'name' => 'pull',
                                'options' => [
                                    '1' => __('Yes'),
                                    '0' => __('No')
                                ]
                            ]
                        ]
                    ],
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/servers'
]);
?>
<!-- <script type="text/javascript">
$(function() {
    popoverStartup();
    $('.rearrange-up').on('click', function() {
        moveIndexRow($(this).data('server-id'), 'up', '/servers/changePriority');
    });
    $('.rearrange-down').on('click', function() {
        moveIndexRow($(this).data('server-id'), 'down', '/servers/changePriority');
    });
});
</script> -->
