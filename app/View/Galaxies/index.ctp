<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $galaxyList,
            'top_bar' => array(
                'children' => array(
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
                )
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
