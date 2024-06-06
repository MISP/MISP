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
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'active' => $context === 'all',
                                'url' => sprintf('%s/eventReports/index/context:all', $baseurl),
                                'text' => __('All'),
                            ),
                            array(
                                'active' => $context === 'default',
                                'class' => 'defaultContext',
                                'url' => sprintf('%s/eventReports/index/context:default', $baseurl),
                                'text' => __('Default'),
                            ),
                            array(
                                'active' => $context === 'deleted',
                                'url' => sprintf('%s/event_reports/index/context:deleted', $baseurl),
                                'text' => __('Deleted'),
                            ),
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
            'title' => __('Event Reports %s', !empty($event_id) ?__('for Event %s', h($event_id)) : ''),
            'primary_id_path' => 'EventReport.id',
            'fields' => array(
                array(
                    'name' => __('ID'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'EventReport.id',
                    'element' => 'links',
                    'url' => $baseurl . '/eventReports/view/%s'
                ),
                array(
                    'name' => __('Context'),
                    'sort' => 'uuid',
                    'class' => 'short',
                    'data_path' => 'EventReport.uuid',
                    'notes_data_path' => 'Note',
                    'opinions_data_path' => 'Opinion',
                    'relationships_data_path' => 'Relationship',
                    'relationships_inbound_data_path' => 'RelationshipInbound',
                    'element' => 'shortUUIDWithNotes',
                    'object_type' => 'EventReport',
                ),
                array(
                    'name' => __('Name'),
                    'data_path' => 'EventReport.name',
                ),
                array(
                    'name' => __('Event ID'),
                    'sort' => 'event_id',
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
                    'element' => 'distribution_levels',
                    'class' => 'short',
                    'data_path' => 'EventReport.distribution',
                )
            ),
            'actions' => array(
                array(
                    'url' => '/eventReports/view',
                    'url_params_data_paths' => array(
                        'EventReport.id'
                    ),
                    'icon' => 'eye',
                    'dbclickAction' => true
                ),
                array(
                    'url' => '/eventReports/edit',
                    'url_params_data_paths' => array(
                        'EventReport.id'
                    ),
                    'icon' => 'edit',
                    'complex_requirement' => function (array $row) {
                        return $this->Acl->canEditEventReport($row);
                    }
                ),
                array(
                    'title' => __('Delete'),
                    'icon' => 'trash',
                    'onclick' => 'simplePopup(\'' . $baseurl . '/event_reports/delete/[onclick_params_data_path]\');',
                    'onclick_params_data_path' => 'EventReport.id',
                    'complex_requirement' => function (array $row) {
                        return $this->Acl->canEditEventReport($row) && !$row['EventReport']['deleted'];
                    }
                ),
                array(
                    'title' => __('Restore report'),
                    'url' => $baseurl . '/event_reports/restore',
                    'url_params_data_paths' => array('EventReport.id'),
                    'icon' => 'trash-restore',
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to restore the Report?'),
                    'complex_requirement' => function (array $row) {
                        return $this->Acl->canEditEventReport($row) && $row['EventReport']['deleted'];
                    }
                ),
            )
        )
    ));
    if (!$embedded_view) {
        echo '</div>';
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'eventReports', 'menuItem' => 'index'));
    }
