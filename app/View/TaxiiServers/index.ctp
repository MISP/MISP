<?php
    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'type' => 'simple',
                            'children' => [
                                'data' => [
                                    'type' => 'simple',
                                    'text' => __('Add TAXII Server'),
                                    'class' => 'btn btn-primary',
                                    'onClick' => 'openGenericModal',
                                    'onClickParams' => [
                                        sprintf(
                                            '%s/taxiiServers/add',
                                            $baseurl
                                        )
                                    ]
                                ]
                            ]
                        ],
                        [
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => [
                    [
                        'name' => __('Id'),
                        'sort' => 'TaxiiServer.id',
                        'data_path' => 'TaxiiServer.id'
                    ],
                    [
                        'name' => __('Name'),
                        'sort' => 'TaxiiServer.name',
                        'data_path' => 'TaxiiServer.name'
                    ],
                    [
                        'name' => __('Baseurl'),
                        'sort' => 'TaxiiServer.baseurl',
                        'data_path' => 'TaxiiServer.baseurl'
                    ],
                    [
                        'name' => __('API root'),
                        'sort' => 'TaxiiServer.api_root',
                        'data_path' => 'TaxiiServer.api_root'
                    ],
                    [
                        'name' => __('Collection'),
                        'sort' => 'TaxiiServer.collection',
                        'data_path' => 'TaxiiServer.collection'
                    ],
                    [
                        'name' => __('Filters'),
                        'sort' => 'TaxiiServer.filters',
                        'data_path' => 'TaxiiServer.filters',
                        'type' => 'json'
                    ],
                    [
                        'name' => __('api_key'),
                        'sort' => 'TaxiiServer.api_key',
                        'data_path' => 'TaxiiServer.api_key'
                    ],
                    [
                        'name' => __('Description'),
                        'sort' => 'TaxiiServer.description',
                        'data_path' => 'TaxiiServer.description'
                    ]
                ],
                'title' => empty($ajax) ? __('Linked TAXII Servers') : false,
                'description' => empty($ajax) ? __('You can connect your MISP to one or several TAXII servers to push data to using a set of filters.') : false,
                'actions' => [
                    [
                        'url' => $baseurl . '/taxiiServers/view',
                        'url_params_data_paths' => ['TaxiiServer.id'],
                        'icon' => 'eye'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/taxiiServers/push/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'TaxiiServer.id',
                        'title' => __('Pull all filtered data to TAXII server'),
                        'icon' => 'upload'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/taxiiServers/edit/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'TaxiiServer.id',
                        'title' => __('Edit TAXII server configuration'),
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/taxiiServers/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'TaxiiServer.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
