<?php
    $fields = [
        [
            'name' => __('Id'),
            'sort' => 'Log.id',
            'data_path' => 'Log.id'
        ],
        [
            'name' => __('Created'),
            'sort' => 'Log.created',
            'data_path' => 'Log.created'
        ],
        [
            'name' => __('IP'),
            'sort' => 'Log.ip',
            'data_path' => 'Log.ip',
            'requirement' => Configure::read('MISP.log_client_ip')
        ],
        [
            'name' => __('Email'),
            'sort' => 'Log.email',
            'data_path' => 'Log.email'
        ],
        [
            'name' => __('Org'),
            'sort' => 'Log.org',
            'data_path' => 'Log.org'
        ],
        [
            'name' => __('Model'),
            'sort' => 'Log.model',
            'data_path' => 'Log.model'
        ],
        [
            'name' => __('Model ID'),
            'sort' => 'Log.model_id',
            'data_path' => 'Log.model_id'
        ],
        [
            'name' => __('Action'),
            'sort' => 'Log.action',
            'data_path' => 'Log.action'
        ],
        [
            'name' => __('Title'),
            'sort' => 'Log.title',
            'data_path' => 'Log.title'
        ],
        [
            'name' => __('Change'),
            'sort' => 'Log.change',
            'data_path' => 'Log.change',
        ],

    ];

    foreach ($validFilters as $filterName => $filterData) {
        $children[] = [
            'text' => h($filterData['name']),
            'title' => __('Modify filters'),
            'active' => isset($filter) && $filterName === $filter,
            'url' => $baseurl . '/logs/index/filter:' . h($filterName)
        ];
    }
    $children[] = [
        'requirement' => !empty($filter),
        'url' => $baseurl . '/logs/index',
        'title' => __('Remove filters'),
        'fa-icon' => 'times'
    ];
    if (isset($search_token)) {
        $passedArgsArray = [
            'search_token' => $search_token
        ];
    }
    echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
    echo $this->element('genericElements/IndexTable/index_table', [
        'data' => [
            'light_paginator' => 1,
            'data' => $data,
            'top_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'simple',
                        'children' => [[
                            'text' => __('Search'),
                            'title' => __('Set search filters'),
                            'onClick' => 'openGenericModal',
                            'onClickParams' => [
                                sprintf(
                                    '%s/logs/search',
                                    $baseurl
                                )
                            ]
                        ]]
                    ],
                    [
                        'type' => 'simple',
                        'children' => $children
                    ]
                    ]
            ],
            'fields' => $fields,
            'title' => __('Application Logs'),
            'persistUrlParams' => $paramArray
        ],
        'passedArgsArray' => $passedArgsArray,
    ]);
    echo '</div>';
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
    }
    
?>

