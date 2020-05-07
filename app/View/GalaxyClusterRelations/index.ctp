<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $data,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'active' => $context === 'all',
                                'url' => sprintf('%s/galaxy_cluster_relations/index/context:all', $baseurl),
                                'text' => __('All'),
                            ),
                            array(
                                'active' => $context === 'default',
                                'url' => sprintf('%s/galaxy_cluster_relations/index/context:default', $baseurl),
                                'text' => __('Default Galaxy Cluster Relations'),
                            ),
                            array(
                                'active' => $context === 'custom',
                                'url' => sprintf('%s/galaxy_cluster_relations/index/context:custom', $baseurl),
                                'text' => __('Custom Galaxy Cluster Relations'),
                            ),
                            array(
                                'active' => $context === 'org',
                                'url' => sprintf('%s/galaxy_cluster_relations/index/context:org', $baseurl),
                                'text' => __('My Galaxy Clusters Relations'),
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
                    'data_path' => 'GalaxyClusterRelation.id',
                ),
                array(
                    'name' => __('Owner Org'),
                    'class' => 'short',
                    'element' => 'org',
                    'data_path' => 'Org',
                    'fields' => array(
                        'allow_picture' => true,
                        'default_org' => 'MISP'
                    ),
                    'requirement' => $isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))
                ),
                array(
                    'name' => __('Creator Org'),
                    'class' => 'short',
                    'element' => 'org',
                    'data_path' => 'Orgc',
                    'fields' => array(
                        'allow_picture' => true,
                        'default_org' => 'MISP'
                    ),
                    'requirement' => (Configure::read('MISP.showorg') || $isAdmin) || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))
                ),
                array(
                    'name' => __('Default'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'GalaxyClusterRelation.default',
                ),
                array(
                    'name' => __('Galaxy Cluster Source'),
                    'sort' => 'GalaxyCluster.tag_name',
                    'element' => 'links',
                    'data_path' => 'GalaxyCluster.tag_name',
                    'url_params_data_paths' => 'GalaxyCluster.id',
                    'url' => $baseurl . '/galaxy_clusters/view'
                ),
                array(
                    'name' => __('Galaxy Cluster Target'),
                    'sort' => 'ReferencedGalaxyCluster.tag_name',
                    'element' => 'links',
                    'data_path' => 'ReferencedGalaxyCluster.tag_name',
                    'url_params_data_paths' => 'ReferencedGalaxyCluster.id',
                    'url' => $baseurl . '/galaxy_clusters/view'
                ),
                array(
                    'name' => __('Relationship Type'),
                    'sort' => 'type',
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterRelation.referenced_galaxy_cluster_type',
                ),
                // array(
                //     'name' => __('Relationship Tag'),
                //     'class' => 'short',
                //     'data_path' => 'Tag',
                //     'element' => 'GalaxyClusterRelationTag'
                // ),
                array(
                    'name' => __('Distribution'),
                    'sort' => 'distribution',
                    'data_path' => 'GalaxyClusterRelation.distribution',
                    'element' => 'distribution_levels'
                ),
            ),
            'title' => __('Galaxy Cluster Relationships Index'),
            'description' => __('List all relationships between Galaxy Clusters'),
            'actions' => array(
                array(
                    'title' => 'Edit',
                    'url' => '/galaxy_cluster_relations/edit',
                    'url_params_data_paths' => array(
                        'GalaxyClusterRelation.id'
                    ),
                    'icon' => 'edit',
                    'complex_requirement' => array(
                        'function' => function($row, $options) {
                            return ($options['me']['org_id'] == $options['datapath']['org']);
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'org' => 'GalaxyClusterRelation.org_id'
                            )
                        )
                    ),
                ),
                array(
                    'title' => 'Delete',
                    'url' => '/galaxy_cluster_relations/delete',
                    'url_params_data_paths' => array(
                        'GalaxyClusterRelation.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the Relationship?'),
                    'icon' => 'trash'
                ),
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxy_cluster_relations', 'menuItem' => 'index'));
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
