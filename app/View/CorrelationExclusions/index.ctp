<?php
    echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
    echo $this->element('genericElements/IndexTable/index_table', [
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
                                'fa-icon' => 'plus',
                                'text' => __('Add correlation exclusion entry'),
                                'class' => 'btn btn-primary modal-open',
                                'url' => "$baseurl/correlation_exclusions/add",
                            ]
                        ]
                    ],
                    [
                        'type' => 'simple',
                        'children' => [
                            'data' => [
                                'type' => 'simple',
                                'text' => __('Clean up correlations'),
                                'class' => 'btn btn-primary modal-open',
                                'url' => "$baseurl/correlation_exclusions/clean",
                            ]
                        ]
                    ],
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'searchKey' => 'quickFilter',
                        'cancel' => [
                            'fa-icon' => 'times',
                            'title' => __('Remove filters'),
                            'onClick' => 'cancelSearch',
                        ],
                    ]
                ]
            ],
            'fields' => [
                [
                    'name' => '#',
                    'sort' => 'CorrelationExclusion.id',
                    'data_path' => 'CorrelationExclusion.id',
                    'class' => 'short'
                ],
                [
                    'name' => 'Value',
                    'sort' => 'CorrelationExclusion.value',
                    'data_path' => 'CorrelationExclusion.value',
                ],
                [
                    'name' => 'Comment',
                    'data_path' => 'CorrelationExclusion.comment',
                ],
                [
                    'name' => 'JSON source',
                    'sort' => 'CorrelationExclusion.from_json',
                    'data_path' => 'CorrelationExclusion.from_json',
                    'element' => 'boolean',
                    'class' => 'short'
                ]
            ],
            'title' => empty($ajax) ? __('Correlation Exclusions Index') : false,
            'description' => empty($ajax) ? __('A list of values to exclude from the correlation engine.') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/correlation_exclusions/edit/[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'CorrelationExclusion.id',
                    'icon' => 'edit',
                    'title' => __('Edit exclusion entry'),
                ],
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/correlation_exclusions/delete/[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'CorrelationExclusion.id',
                    'icon' => 'trash',
                    'title' => __('Delete correlation exclusion entry'),
                ]
            ]
        ]
    ]);
    echo '</div>';
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
    }
?>
<script>
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
