<?php
    echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
    echo $this->element('genericElements/IndexTable/index_table', [
        'data' => [
            'stupid_pagination' => 1,
            'data' => $data,
            'top_bar' => [
                'pull' => 'right',
                'children' => [
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
                    'name' => 'Value',
                    'sort' => 'Correlation.value',
                    'data_path' => 'Correlation.value',
                    'class' => 'short'
                ],
                [
                    'name' => 'Correlation count',
                    'sort' => 'Correlation.count',
                    'data_path' => 'Correlation.count'
                ]
            ],
            'title' => empty($ajax) ? $title_for_layout : false,
            'description' => empty($ajax) ? __('The values with the most correlation entries.') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/correlation_exclusions/add/redirect:top_correlations/value:[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'Correlation.value',
                    'icon' => 'trash',
                    'title' => __('Add exclusion entry for value'),
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
