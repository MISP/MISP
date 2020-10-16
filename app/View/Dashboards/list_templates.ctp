<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $data,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value'
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('Id'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'Dashboard.id',
                ),
                array(
                    'name' => __('UUID'),
                    'sort' => 'uuid',
                    'class' => 'short',
                    'data_path' => 'Dashboard.uuid',
                ),
                array(
                    'name' => __('Owner'),
                    'sort' => 'User.email',
                    'class' => 'short',
                    'data_path' => 'User.email',
                ),
                array(
                    'name' => __('Name'),
                    'sort' => 'name',
                    'class' => 'short',
                    'data_path' => 'Dashboard.name',
                ),
                array(
                    'name' => __('Description'),
                    'data_path' => 'Dashboard.description',
                ),
                array(
                    'name' => __('Widgets Used'),
                    'data_path' => 'Dashboard.widgets',
                    'element' => 'list'
                ),
                array(
                    'name' => __('Selectable'),
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Dashboard.selectable',
                ),
                array(
                    'name' => __('Default'),
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Dashboard.default',
                )
            ),
            'title' => __('Dashboard Templates Index'),
            'description' => __('Users can create and save dashboard templates. Additionally, administrators can create selectable templates for the community and select a default to be used by new users.'),
            'actions' => array(
                array(
                    'url' => '/dashboards/index',
                    'url_params_data_paths' => array(
                        'Dashboard.uuid'
                    ),
                    'title' => 'Load and set template',
                    'icon' => 'eye'
                ),
                array(
                    'onclick' => 'openGenericModal(\'' . $baseurl . '/dashboards/saveTemplate/[onclick_params_data_path]\');',
                    'onclick_params_data_path' => 'Dashboard.uuid',
                    'icon' => 'edit'
                ),
                array(
                    'url' => '/dashboards/deleteTemplate',
                    'url_params_data_paths' => array(
                        'Dashboard.uuid'
                    ),
                    'postLink' => 1,
                    'postLinkConfirm' => __('Are you sure you want to remove this dashboard template?'),
                    'icon' => 'trash'
                )
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'dashboard', 'menuItem' => 'dashboardTemplateIndex'));
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo json_encode($passedArgs); ?>;
    $(document).ready(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
