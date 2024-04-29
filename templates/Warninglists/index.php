<?php
$fields = [
    [
        'name' => __('ID'),
        'sort' => 'id',
        'class' => 'short',
        'data_path' => 'id',
        // 'element' => 'links',
        // 'url' => $baseurl . '/warninglists/view/%s',
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name',
    ],
    [
        'name' => __('Version'),
        'sort' => 'version',
        'class' => 'short',
        'data_path' => 'version',
    ],
    [
        'name' => __('Description'),
        'data_path' => 'description',
    ],
    [
        'name' => __('Category'),
        'sort' => 'category',
        'class' => 'short',
        'element' => 'custom',
        'function' => function (array|\App\Model\Entity\Warninglist $row) use ($possibleCategories) {
            return $possibleCategories[$row['category']];
        },
    ],
    [
        'name' => __('Type'),
        'sort' => 'type',
        'class' => 'short',
        'data_path' => 'type',
    ],
    [
        'name' => __('Entries'),
        'sort' => 'warninglist_entry_count',
        'class' => 'short',
        'data_path' => 'warninglist_entry_count',
    ],
    [
        'name' => __('Default'),
        'sort' => 'default',
        'class' => 'short',
        'element' => 'boolean',
        'data_path' => 'default',
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'enabled',
        'class' => 'short',
        'element' => 'toggle',
        'data_path' => 'enabled',
        'url' => '/warninglists/toggleEnable',
        'url_params_vars' => [['datapath' => ['id']]],
        'requirement' => $loggedUser['Role']['perm_site_admin'],
    ],
];

// echo '<div class="index">';
// if ($isSiteAdmin) {
//     echo '<div id="hiddenFormDiv">';
//     echo $this->Form->create('Warninglist', ['url' => $baseurl . '/warninglists/toggleEnable']);
//     echo $this->Form->input('data', ['label' => false, 'style' => 'display:none;']);
//     echo $this->Form->end();
//     echo '</div>';
// }
echo $this->element(
    '/genericElements/IndexTable/index_table',
    [
        'data' => [
            'data' => $data,
            'top_bar' => [
                'children' => [
                    // FIXME chri  filtering
                    // [
                    //     'type' => 'simple',
                    //     'children' => [
                    //         [
                    //             'url' => $baseurl . '/warninglists/index',
                    //             'text' => __('All'),
                    //             'active' => !isset($passedArgsArray['enabled']),
                    //         ],
                    //         [
                    //             'url' => $baseurl . '/warninglists/index/enabled:1',
                    //             'text' => __('Enabled'),
                    //             'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === '1',
                    //         ],
                    //         [
                    //             'url' => $baseurl . '/warninglists/index/enabled:0',
                    //             'text' => __('Disabled'),
                    //             'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === '0',
                    //         ],
                    //     ],
                    // ],
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value',
                        'allowFilering' => true,
                    ],
                ],
            ],
            'title' => __('Warninglists'),
            'primary_id_path' => 'id',
            'fields' => $fields,
            'actions' => [
                [
                    'url' => '/warninglists/view',
                    'url_params_data_paths' => ['id'],
                    'icon' => 'eye',
                ],
                // [
                //     'title' => __('Enable'),
                //     'icon' => 'play',
                //     'onclick' => sprintf('toggleSetting(%s, \'%s\', \'%s\')', 'event', 'warninglist_enable', '[onclick_params_data_path]'),
                //     'onclick_params_data_path' => 'id',
                //     'complex_requirement' => [
                //         'function' => function ($row, $options) use ($loggedUser) {
                //             return $loggedUser['Role']['perm_site_admin'] && !$options['datapath']['enabled'];
                //         },
                //         'options' => [
                //             'datapath' => [
                //                 'orgc' => 'Event.orgc_id',
                //                 'enabled' => 'enabled',
                //             ],
                //         ],
                //     ],
                // ],
                // [
                //     'title' => __('Disable'),
                //     'icon' => 'stop',
                //     'onclick' => sprintf('toggleSetting(%s, \'%s\', \'%s\')', 'event', 'warninglist_enable', '[onclick_params_data_path]'),
                //     'onclick_params_data_path' => 'id',
                //     'complex_requirement' => [
                //         'function' => function ($row, $options) use ($loggedUser) {
                //             return $loggedUser['Role']['perm_site_admin'] && $options['datapath']['enabled'];
                //         },
                //         'options' => [
                //             'datapath' => [
                //                 'enabled' => 'enabled',
                //             ],
                //         ],
                //     ],
                // ],
                [
                    'open_modal' => '/warninglists/edit/[onclick_params_data_path]',
                    'modal_params_data_path' => 'id',
                    'icon' => 'edit',
                    'complex_requirement' => [
                        'function' => function ($row) use ($loggedUser) {
                            return $row['default'] == 0 && ($loggedUser['Role']['perm_warninglist'] || $loggedUser['Role']['perm_site_admin']);
                        },
                    ],
                ],
                [
                    'open_modal' => '/warninglists/delete/[onclick_params_data_path]',
                    'modal_params_data_path' => 'id',
                    'icon' => 'trash',
                    'requirement' => $loggedUser['Role']['perm_site_admin'],
                ],
            ],
        ],
    ]
);
// echo '</div>';
// echo $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'warninglist', 'menuItem' => 'index']);
