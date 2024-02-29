<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $response,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'url' => sprintf('%s/analyst_data_blocklists/add/', $baseurl),
                                'text' => __('+ Add entry to blocklist'),
                            ),
                        )
                    ),
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'searchall'
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('Id'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'AnalystDataBlocklist.id',
                ),
                array(
                    'name' => __('Org'),
                    'class' => 'short',
                    'data_path' => 'AnalystDataBlocklist.analyst_data_orgc',
                ),
                array(
                    'name' => __('Analyst Data UUID'),
                    'class' => 'short',
                    'data_path' => 'AnalystDataBlocklist.analyst_data_uuid',
                ),
                array(
                    'name' => __('Created'),
                    'sort' => 'created',
                    'class' => 'short',
                    'data_path' => 'AnalystDataBlocklist.created',
                ),
                array(
                    'name' => __('Analyst Data value'),
                    'sort' => 'value',
                    'class' => 'short',
                    'data_path' => 'AnalystDataBlocklist.analyst_data_info',
                ),
                array(
                    'name' => __('Comment'),
                    'sort' => 'comment',
                    'class' => 'short',
                    'data_path' => 'AnalystDataBlocklist.comment',
                ),
            ),
            'title' => __('Analyst Data Blocklist Index'),
            'description' => __('List all analyst data that will be prevented to be created (also via synchronization) on this instance'),
            'actions' => array(
                array(
                    'title' => 'Delete',
                    'url' => $baseurl . '/analyst_data_blocklists/delete',
                    'url_params_data_paths' => array(
                        'AnalystDataBlocklist.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the entry?'),
                    'icon' => 'trash'
                ),
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'analyst_data', 'menuItem' => 'index_blocklist'));
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    if (passedArgsArray['context'] === undefined) {
        passedArgsArray['context'] = 'pending';
    }
    $(document).ready(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter('/context:' + passedArgsArray['context']);
        });
        $('#quickFilterField').on('keypress', function (e) {
            if(e.which === 13) {
                runIndexQuickFilter('/context:' + passedArgsArray['context']);
            }
        });
    });
</script>
