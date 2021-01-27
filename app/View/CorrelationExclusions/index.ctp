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
                                'text' => __('Add correlation exclusion entry'),
                                'class' => 'btn btn-primary',
                                'onClick' => 'openGenericModal',
                                'onClickParams' => [
                                    sprintf(
                                        '%s/correlation_exclusions/add',
                                        $baseurl
                                    )
                                ]
                            ]
                        ]
                    ],
                    [
                        'type' => 'simple',
                        'children' => [
                            'data' => [
                                'type' => 'simple',
                                'text' => __('Clean up correlations'),
                                'class' => 'btn btn-primary',
                                'onClick' => 'openGenericModal',
                                'onClickParams' => [
                                    sprintf(
                                        '%s/correlation_exclusions/clean',
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
                        'searchKey' => 'quickFilter',
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
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
