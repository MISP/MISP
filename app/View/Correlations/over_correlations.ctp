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
                            'type' => 'simple',
                            'url' => $baseurl . '/correlations/overCorrelations',
                            'text' => __('All'),
                            'active' => $scope === 'all',
                        ],
                        [
                            'type' => 'simple',
                            'url' => $baseurl . '/correlations/overCorrelations/scope:over_correlating',
                            'text' => __('Over-correlating'),
                            'active' => $scope === 'over_correlating',
                        ],
                        [
                            'type' => 'simple',
                            'url' => $baseurl . '/correlations/overCorrelations/scope:not_over_correlating',
                            'text' => __('Not over-correlating'),
                            'active' => $scope === 'not_over_correlating',
                        ],
                        [
                            'type' => 'simple',
                            'url' => $baseurl . '/correlations/generateOccurrences',
                            'text' => __('Regenerate occurrence counts')
                        ]
                    ]
                ]
            ]
        ],
        'fields' => [
            [
                'name' => 'Value',
                'element' => 'postlink',
                'data_path' => 'OverCorrelatingValue.value',
                'url' => '/attributes/search/results',
                'payload_paths' => [
                    'value' => 'OverCorrelatingValue.value'
                ]
            ],
            [
                'name' => 'Occurrences',
                'data_path' => 'OverCorrelatingValue.occurrence',
                'class' => 'shortish'
            ],
            [
                'name' => 'Blocked by Threshold',
                'data_path' => 'OverCorrelatingValue.over_correlation',
                'class' => 'shortish',
                'element' => 'boolean'
            ],
            [
                'name' => 'Excluded by Exclusion List',
                'data_path' => 'OverCorrelatingValue.excluded',
                'class' => 'shortish',
                'element' => 'boolean'
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
                'onclick_params_data_path' => 'OverCorrelatingValue.value',
                'icon' => 'trash',
                'title' => __('Add exclusion entry for value'),
                'complex_requirement' => [
                    'function' => function (array $row) {
                        return !$row['OverCorrelatingValue']['excluded'];
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


