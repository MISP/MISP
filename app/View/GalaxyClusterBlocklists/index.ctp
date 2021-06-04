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
                                'url' => sprintf('%s/galaxy_cluster_blocklists/add/', $baseurl),
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
                    'data_path' => 'GalaxyClusterBlocklist.id',
                ),
                array(
                    'name' => __('Org'),
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterBlocklist.cluster_orgc',
                ),
                array(
                    'name' => __('Galaxy Cluster UUID'),
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterBlocklist.cluster_uuid',
                ),
                array(
                    'name' => __('Created'),
                    'sort' => 'created',
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterBlocklist.created',
                ),
                array(
                    'name' => __('Cluster value'),
                    'sort' => 'value',
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterBlocklist.cluster_info',
                ),
                array(
                    'name' => __('Comment'),
                    'sort' => 'comment',
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterBlocklist.comment',
                ),
            ),
            'title' => __('Galaxy Cluster Blocklist Index'),
            'description' => __('List all galaxy clusters that will be prevented to be created (also via synchronization) on this instance'),
            'actions' => array(
                array(
                    'title' => 'Edit',
                    'url' => '/galaxy_cluster_blocklists/edit',
                    'url_params_data_paths' => array(
                        'GalaxyClusterBlocklist.id'
                    ),
                    'icon' => 'edit',
                ),
                array(
                    'title' => 'Delete',
                    'url' => $baseurl . '/galaxy_cluster_blocklists/delete',
                    'url_params_data_paths' => array(
                        'GalaxyClusterBlocklist.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the entry?'),
                    'icon' => 'trash'
                ),
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'index_blocklist'));
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
