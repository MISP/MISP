
<?php
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'data' => $data,
            'title' =>__('Signature Allowedlist'),
            'description' => __('Regex entries (in the standard php regex /{regex}/{modifier} format) entered below will restrict matching attributes from being included in the IDS flag sensitive exports (such as NIDS exports).'),
            'primary_id_path' => 'id',
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'simple',
                        'children' => [
                            'data' => [
                                'type' => 'simple',
                                'text' => __('Add entry'),
                                'class' => 'btn btn-primary',
                                'popover_url' => '/admin/allowedlists/add',
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
            'fields' => [
                [
                    'name' => __('ID'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'id'
                ],
                [
                    'name' => __('Name'),
                    'sort' => 'name',
                    'data_path' => 'name'
                ],
            ],
            'actions' => [
                [
                    'open_modal' => '/admin/allowedlists/edit/[onclick_params_data_path]',
                    'modal_params_data_path' => 'id',
                    'icon' => 'edit',
                    'title' => __('Edit allowlist entry'),
                    'requirement' => $loggedUser['Role']['perm_admin']
                ],
                [
                    'open_modal' => '/admin/allowedlists/delete/[onclick_params_data_path]',
                    'modal_params_data_path' => 'id',
                    'icon' => 'trash',
                    'title' => __('Delete allowlist entry'),
                    'requirement' => $loggedUser['Role']['perm_admin']
                ]
            ]
        ]
    ]);
    ?>
</div>