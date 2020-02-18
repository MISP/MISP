<?php
    if(!$embedded_view) {
        echo '<div class="index">';
    }
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $reports,
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
                    'data_path' => 'EventReport.id',
                ),
                array(
                    'name' => __('Name'),
                    'data_path' => 'EventReport.name',
                ),
                array(
                    'name' => __('Event ID'),
                    'class' => 'short',
                    'element' => 'links',
                    'data_path' => 'EventReport.event_id',
                    'url' => $baseurl . '/events/view/%s'
                ),
                array(
                    'name' => __('Last update'),
                    'sort' => 'timestamp',
                    'class' => 'short',
                    'element' => 'datetime',
                    'data_path' => 'EventReport.timestamp',
                ),
                array(
                    'name' => __('Distribution'),
                    'class' => 'short',
                    'data_path' => 'EventReport.distribution',
                )
            ),
            'title' => sprintf(__('Event Reports %s'), !empty($event_id) ? sprintf(__('for Event %s'), h($event_id)) : ''),
            'actions' => array(
                array(
                    'url' => '/eventReports/view',
                    'url_params_data_paths' => array(
                        'EventReport.id'
                    ),
                    'icon' => 'eye'
                ),
                array(
                    'url' => '/eventReports/edit',
                    'url_params_data_paths' => array(
                        'EventReport.id'
                    ),
                    'icon' => 'edit'
                )
            )
        )
    ));
    if(!$embedded_view) {
        echo '</div>';
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-report', 'menuItem' => 'index'));
    }
?>
