<?php
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'paginatorOptions' => array(
                'update' => '#clusters_div',
            ),
            'data' => $list,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'active' => $context === 'all',
                                'url' => sprintf('%s/galaxies/view/%s/context:all', $baseurl, $galaxy_id),
                                'text' => __('All'),
                            ),
                            // array(
                            //     'active' => $context === 'altered',
                            //     'url' => sprintf('%s/galaxies/view/%s/context:altered', $baseurl, $galaxy_id),
                            //     'text' => __('Altered Galaxy Clusters'),
                            // )
                        )
                    ),
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('Value'),
                    'sort' => 'GalaxyCluster.value',
                    'element' => 'links',
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.value',
                    'url_params_data_paths' => 'GalaxyCluster.id',
                    'url' => $baseurl . '/galaxy_clusters/view'
                ),
                array(
                    'name' => __('Synonyms'),
                    'sort' => 'name',
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.synonyms',
                ),
                array(
                    'name' => __('Activity'),
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.id',
                    'csv' => array('scope' => 'cluster', 'data' => $csv),
                    'element' => 'sparkline'
                ),
                array(
                    'name' => __('#Events'),
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.event_count',
                ),
                array(
                    'name' => __('Description'),
                    'sort' => 'description',
                    'data_path' => 'GalaxyCluster.description',
                ),
            ),
            'actions' => array(
                array(
                    'title' => 'View graph',
                    'url' => '/galaxies/viewGraph',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'icon' => 'share-alt',
                ),
                array(
                    'title' => 'View',
                    'url' => '/galaxy_clusters/view',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'icon' => 'eye',
                    'dbclickAction' => true
                ),
                array(
                    'title' => 'Delete',
                    'url' => '/galaxy_clusters/delete',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the Galaxy Cluster?'),
                    'icon' => 'trash'
                ),
            )
        )
    ));
?>

<script type="text/javascript">
    $(document).ready(function(){
        var passedArgsArray = <?php echo $passedArgs; ?>;
        var galaxyId = "<?php echo h($galaxy_id); ?>";
        if (passedArgsArray['context'] === undefined || passedArgsArray['context'] === "") {
            passedArgsArray['context'] = 'all';
        }
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter('/' + galaxyId + '/context:' + passedArgsArray['context']);
        });
    });
</script>
<?php echo $this->Js->writeBuffer(); ?>
