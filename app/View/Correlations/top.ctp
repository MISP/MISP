<?php
    echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
    echo $this->element('genericElements/IndexTable/index_table', [
        'data' => [
            'light_paginator' => 1,
            'data' => $data,
            'top_bar' => [
                'children' => [
                    [
                        'children' => [
                            [
                                'type' => 'text',
                                'text' => __('Cache age: %s%s', $age, $age_unit)
                            ],
                            [
                                'type' => 'simple',
                                'url' => $baseurl . '/correlations/generateTopCorrelations',
                                'text' => __('Regenerate cache')
                            ]
                        ]
                    ]
                ]
            ],
            'fields' => [
                [
                    'name' => 'Value',
                    'element' => 'postlink',
                    'data_path' => 'Correlation.value',
                    'url' => '/attributes/search/results',
                    'payload_paths' => [
                        'value' => 'Correlation.value'
                    ]
                ],
                [
                    'name' => 'Excluded',
                    'data_path' => 'Correlation.excluded',
                    'element' => 'boolean',
                    'class' => 'short'
                ],
                [
                    'name' => 'Correlation count',
                    'data_path' => 'Correlation.count',
                    'class' => 'shortish'
                ]
            ],
            'title' => empty($ajax) ? h($title_for_layout) : false,
            'description' => empty($ajax) ? __('The values with the most correlation entries.') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/correlation_exclusions/add/redirect_controller:correlations/redirect:top/value:[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'Correlation.value',
                    'icon' => 'trash',
                    'title' => __('Add exclusion entry for value'),
                    'complex_requirement' => [
                        'function' => function (array $row) {
                            return !$row['Correlation']['excluded'];
                        }
                    ]
                ]
            ]
        ]
    ]);
    echo '</div>';
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
    }


