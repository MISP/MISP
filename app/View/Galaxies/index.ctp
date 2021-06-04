<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $galaxyList,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'url' => $baseurl . '/galaxies/index',
                                'text' => __('All'),
                                'active' => !isset($passedArgsArray['enabled']),
                            ),
                            array(
                                'url' => $baseurl . '/galaxies/index/enabled:1',
                                'text' => __('Enabled'),
                                'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "1",
                            ),
                            array(
                                'url' => $baseurl . '/galaxies/index/enabled:0',
                                'text' => __('Disabled'),
                                'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "0",
                            )
                        )
                    ),
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'searchKey' => 'value',
                        'cancel' => array(
                            'fa-icon' => 'times',
                            'title' => __('Remove filters'),
                            'onClick' => 'cancelSearch',
                        )
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('Galaxy Id'),
                    'sort' => 'Galaxy.id',
                    'element' => 'links',
                    'class' => 'short',
                    'data_path' => 'Galaxy.id',
                    'url' => $baseurl . '/galaxies/view/%s'
                ),
                array(
                    'name' => __('Icon'),
                    'element' => 'icon',
                    'class' => 'short',
                    'data_path' => 'Galaxy.icon',
                ),
                array(
                    'name' => __('Name'),
                    'sort' => 'name',
                    'class' => 'short',
                    'data_path' => 'Galaxy.name',
                ),
                array(
                    'name' => __('version'),
                    'class' => 'short',
                    'data_path' => 'Galaxy.version',
                ),
                array(
                    'name' => __('Namespace'),
                    'class' => 'short',
                    'data_path' => 'Galaxy.namespace',
                ),
                array(
                    'name' => __('Description'),
                    'data_path' => 'Galaxy.description',
                ),
                array(
                    'name' => __('Enabled'),
                    'element' => 'boolean',
                    'sort' => 'enabled',
                    'class' => 'short',
                    'data_path' => 'Galaxy.enabled',
                ),
            ),
            'title' => __('Galaxy index'),
            'actions' => array(
                array(
                    'url' => '/galaxies/view',
                    'url_params_data_paths' => array(
                        'Galaxy.id'
                    ),
                    'icon' => 'eye',
                    'dbclickAction' => true
                ),
                array(
                    'title' => __('Enable'),
                    'icon' => 'play',
                    'postLink' => true,
                    'url' => $baseurl . '/galaxies/enable',
                    'url_params_data_paths' => ['Galaxy.id'],
                    'postLinkConfirm' => __('Are you sure you want to enable this galaxy library?'),
                    'complex_requirement' => array(
                        'function' => function ($row, $options) use ($isSiteAdmin) {
                            return $isSiteAdmin && !$options['datapath']['enabled'];
                        },
                        'options' => array(
                            'datapath' => array(
                                'enabled' => 'Galaxy.enabled'
                            )
                        )
                    ),
                ),
                array(
                    'title' => __('Disable'),
                    'icon' => 'stop',
                    'postLink' => true,
                    'url' => $baseurl . '/galaxies/disable',
                    'url_params_data_paths' => ['Galaxy.id'],
                    'postLinkConfirm' => __('Are you sure you want to disable this galaxy library?'),
                    'complex_requirement' => array(
                        'function' => function ($row, $options) use ($isSiteAdmin) {
                            return $isSiteAdmin && $options['datapath']['enabled'];
                        },
                        'options' => array(
                            'datapath' => array(
                                'enabled' => 'Galaxy.enabled'
                            )
                        )
                    ),
                ),
                array(
                    'url' => '/galaxies/delete',
                    'url_params_data_paths' => array(
                        'Galaxy.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the Galaxy?'),
                    'icon' => 'trash',
                    'requirement' => $isSiteAdmin,
                ),
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'galaxy_index'));
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
