<?php
    use Cake\Core\Configure;

    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'data' => $data,
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'simple',
                        'children' => [
                            [
                                'url' => $baseurl . '/galaxies/index',
                                'text' => __('All'),
                                'active' => !isset($passedArgsArray['enabled']),
                            ],
                            [
                                'url' => $baseurl . '/galaxies/index?enabled=1',
                                'text' => __('Enabled'),
                                'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "1",
                            ],
                            [
                                'url' => $baseurl . '/galaxies/index?enabled=0',
                                'text' => __('Disabled'),
                                'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "0",
                            ]
                        ]
                    ],
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'searchKey' => 'value',
                        'cancel' => [
                            'fa-icon' => 'times',
                            'title' => __('Remove filters'),
                            'onClick' => 'cancelSearch',
                        ]
                    ]
                ]
            ],
            'fields' => [
                [
                    'name' => __('ID'),
                    'sort' => 'id',
                    'element' => 'links',
                    'class' => 'short',
                    'data_path' => 'id',
                    'url' => $baseurl . '/galaxies/view/{{0}}'
                ],
                [
                    'name' => __('Icon'),
                    'element' => 'icon',
                    'class' => 'short',
                    'data_path' => 'icon',
                ],
                [
                    'name' => __('Name'),
                    'sort' => 'name',
                    'class' => 'short',
                    'data_path' => 'name',
                ],
                [
                    'name' => __('Version'),
                    'class' => 'short',
                    'data_path' => 'version',
                ],
                [
                    'name' => __('Namespace'),
                    'class' => 'short',
                    'sort' => 'namespace',
                    'data_path' => 'namespace',
                ],
                [
                    'name' => __('Description'),
                    'data_path' => 'description',
                ],
                [
                    'name' => __('Enabled'),
                    'element' => 'boolean',
                    'sort' => 'enabled',
                    'class' => 'short',
                    'data_path' => 'enabled',
                ],
                [
                    'name' => __('Local Only'),
                    'element' => 'boolean',
                    'sort' => 'local_only',
                    'class' => 'short',
                    'data_path' => 'local_only',
                ],
            ],
            'title' => __('Galaxy index'),
            'actions' => [
                [
                    'url' => '/galaxies/view',
		            'title' => __('View'),
                    'url_params_data_paths' => [
                        'id'
                    ],
                    'icon' => 'eye',
                    'dbclickAction' => true
                ],
                [
                    'title' => __('Enable'),
                    'icon' => 'play',
                    'postLink' => true,
                    'url' => $baseurl . '/galaxies/enable',
                    'url_params_data_paths' => ['id'],
                    'postLinkConfirm' => __('Are you sure you want to enable this galaxy library?'),
                    'complex_requirement' => function ($row) use ($isSiteAdmin) {
                        return $isSiteAdmin && !$row['enabled'];
                    }
                ],
                [
                    'title' => __('Disable'),
                    'icon' => 'stop',
                    'postLink' => true,
                    'url' => $baseurl . '/galaxies/disable',
                    'url_params_data_paths' => ['id'],
                    'postLinkConfirm' => __('Are you sure you want to disable this galaxy library?'),
                    'complex_requirement' => function ($row) use ($isSiteAdmin) {
                        return $isSiteAdmin && $row['enabled'];
                    }
                ],
                [
                    'url' => '/galaxies/delete',
		            'title' => __('Delete'),
                    'url_params_data_paths' => [
                        'id'
                    ],
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the Galaxy?'),
                    'icon' => 'trash',
                    'requirement' => $isSiteAdmin,
                ],
        ]
        ]
    ]);
?>
<script>
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
