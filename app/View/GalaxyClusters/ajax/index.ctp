<?php
    foreach ($list as $i => $cluster) {
        if ($cluster['GalaxyCluster']['default']) {
            $list[$i]['GalaxyCluster']['published'] = null;
        }
    }
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'containerId' => 'clusters',
        'data' => array(
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
                            array(
                                'active' => $context === 'default',
                                'url' => sprintf('%s/galaxies/view/%s/context:default', $baseurl, $galaxy_id),
                                'text' => __('Default'),
                            ),
                            array(
                                'active' => $context === 'custom',
                                'url' => sprintf('%s/galaxies/view/%s/context:custom', $baseurl, $galaxy_id),
                                'text' => __('Custom'),
                                'badge' => [
                                    'type' => 'info',
                                    'text' => $custom_cluster_count
                                ]
                            ),
                            array(
                                'active' => $context === 'org',
                                'url' => sprintf('%s/galaxies/view/%s/context:orgc', $baseurl, $galaxy_id),
                                'text' => __('My Clusters'),
                            ),
                            array(
                                'active' => $context === 'deleted',
                                'url' => sprintf('%s/galaxies/view/%s/context:deleted', $baseurl, $galaxy_id),
                                'text' => __('Deleted'),
                            ),
                            array(
                                'active' => $context === 'fork_tree',
                                'url' => sprintf('%s/galaxies/view/%s/context:fork_tree', $baseurl, $galaxy_id),
                                'text' => __('View Fork Tree'),
                            ),
                            array(
                                'active' => $context === 'relations',
                                'url' => sprintf('%s/galaxies/view/%s/context:relations', $baseurl, $galaxy_id),
                                'text' => __('View Galaxy Relationships'),
                            ),
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
                    'name' => __('ID'),
                    'sort' => 'GalaxyCluster.id',
                    'element' => 'links',
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.id',
                    'url_params_data_paths' => 'GalaxyCluster.id',
                    'url' => $baseurl . '/galaxy_clusters/view'
                ),
                array(
                    'name' => __('Published'),
                    'sort' => 'GalaxyCluster.published',
                    'element' => 'booleanOrNA',
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.published'
                ),
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
                    'class' => '',
                    'data_path' => 'GalaxyCluster.synonyms',
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
                    'data_path' => 'GalaxyCluster.default',
                ),
                array(
                    'name' => __('Activity'),
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.id',
                    'csv_data_path' => 'csv',
                    'csv' => array('scope' => 'cluster'),
                    'element' => 'sparkline',
                ),
                array(
                    'name' => __('#Events'),
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.event_count',
                ),
                array(
                    'name' => __('#Relations'),
                    'class' => 'short',
                    'data_path' => 'GalaxyCluster.relation_counts',
                    'element' => 'in_out_counts',
                    'fields' => array(
                        'entity_name' => __('cluster'),
                        'inbound_action_name' => __('is being targeted by'),
                        'outbound_action_name' => __('targets'),
                    )
                ),
                array(
                    'name' => __('Description'),
                    'sort' => 'description',
                    'data_path' => 'GalaxyCluster.description',
                    'element' => 'tree',
                    'fields' => array(
                        'tree_data' => array(
                            0 => array(
                                'main_data_path' => 'GalaxyCluster.extended_from',
                                'node_link_path' => 'GalaxyCluster.uuid',
                                'node_link_title' => 'GalaxyCluster.value',
                            ),
                            1 => array(
                                'main_data_path' => 'GalaxyCluster',
                                'node_link_title' => 'value',
                            ),
                            2 => array(
                                'main_data_path' => 'GalaxyCluster.extended_by',
                                'node_link_path' => 'GalaxyCluster.uuid',
                                'node_link_title' => 'GalaxyCluster.value',
                            ),
                        )
                    )
                ),
                array(
                    'name' => __('Distribution'),
                    'sort' => 'distribution',
                    'data_path' => 'GalaxyCluster.distribution',
                    'element' => 'distribution_levels'
                ),
            ),
            'actions' => array(
                array(
                    'title' => __('Restore Cluster'),
                    'url' => '/galaxy_clusters/restore',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'icon' => 'trash-restore',
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to restore the Galaxy Cluster?'),
                    'complex_requirement' => array(
                        'function' => function($row, $options) {
                            return ($options['me']['Role']['perm_site_admin'] || $options['me']['org_id'] == $options['datapath']['orgc']) && $options['datapath']['deleted'];
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'orgc' => 'GalaxyCluster.orgc_id',
                                'deleted' => 'GalaxyCluster.deleted'
                            )
                        )
                    ),
                ),
                array(
                    'title' => __('Publish Cluster'),
                    'url' => '/galaxy_clusters/publish',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'icon' => 'upload',
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to publish the Galaxy Cluster?'),
                    'complex_requirement' => array(
                        'function' => function($row, $options) {
                            return !$options['datapath']['published'] &&
                                (
                                    $options['me']['Role']['perm_site_admin'] ||
                                    ($options['me']['org_id'] == $options['datapath']['orgc'] && $options['me']['Role']['perm_galaxy_editor'] && $options['me']['Role']['perm_publish'])
                                );
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'orgc' => 'GalaxyCluster.orgc_id',
                                'published' => 'GalaxyCluster.published'
                            )
                        )
                    ),
                ),
                array(
                    'title' => __('View correlation graph'),
                    'url' => '/galaxies/viewGraph',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'icon' => 'share-alt',
                ),
                array(
                    'title' => __('Fork'),
                    'url' => '/galaxy_clusters/add',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.galaxy_id'
                    ),
                    'url_named_params_data_paths' => array(
                        'forkUuid' => 'GalaxyCluster.uuid'
                    ),
                    'icon' => 'code-branch',
                    'complex_requirement' => array(
                        'function' => function($row, $options) {
                            return $options['me']['Role']['perm_galaxy_editor'];
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'org' => 'GalaxyCluster.org_id',
                                'default' => 'GalaxyCluster.default'
                            )
                        )
                    ),
                ),
                array(
                    'title' => __('Contribute to misp-galaxy'),
                    'url' => '/galaxy_clusters/export_for_misp_galaxy',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'icon' => 'handshake',
                    'complex_requirement' => array(
                        'function' => function($row, $options) {
                            return empty($row['GalaxyCluster']['default']);
                        },
                    ),
                ),
                array(
                    'title' => __('Edit'),
                    'url' => '/galaxy_clusters/edit',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'icon' => 'edit',
                    'complex_requirement' => array(
                        'function' => function($row, $options) {
                            return !$options['datapath']['default'] &&
                            (
                                $options['me']['Role']['perm_site_admin'] ||
                                ($options['me']['org_id'] == $options['datapath']['org'] && $options['me']['Role']['perm_galaxy_editor'])
                            );
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'org' => 'GalaxyCluster.org_id',
                                'default' => 'GalaxyCluster.default'
                            )
                        )
                    ),
                ),
                array(
                    'title' => __('Delete'),
                    'icon' => 'trash',
                    'onclick' => 'simplePopup(\'' . $baseurl . '/galaxy_clusters/delete/[onclick_params_data_path]\');',
                    'onclick_params_data_path' => 'GalaxyCluster.id',
                    'complex_requirement' => array(
                        'function' => function($row, $options) {
                            return $options['me']['Role']['perm_site_admin'] || ($options['me']['org_id'] == $options['datapath']['org'] && $options['me']['Role']['perm_galaxy_editor']);
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'org' => 'GalaxyCluster.org_id',
                                'default' => 'GalaxyCluster.default'
                            )
                        )
                    ),
                ),
                array(
                    'title' => __('View'),
                    'url' => '/galaxy_clusters/view',
                    'url_params_data_paths' => array(
                        'GalaxyCluster.id'
                    ),
                    'icon' => 'eye',
                    'dbclickAction' => true
                ),
            )
        )
    ));
?>

<script>
    $(function(){
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
