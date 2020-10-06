<div class="shadowAttributes index">
<?php
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $shadowAttributes,
            'primary_id_path' => 'ShadowAttribute.id',
            'top_bar' => array(
                'children' => array(
                    array(
                        'children' => array(
                            array(
                                'text' => __('My Org\'s Events'),
                                'active' => !$all,
                                'url' => $baseurl . '/shadow_attributes/index/all:0'
                            ),
                            array(
                                'text' => __('All Events'),
                                'active' => $all,
                                'url' => $baseurl . '/shadow_attributes/index/all:1'
                            )
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
                    'name' => __('ID'),
                    'sort' => 'ShadowAttribute.id',
                    'class' => 'short',
                    'data_path' => 'ShadowAttribute.id',
                ),
                array(
                    'name' => __('Event ID'),
                    'sort' => 'ShadowAttribute.event_id',
                    'element' => 'links',
                    'class' => 'short',
                    'data_path' => 'ShadowAttribute.event_id',
                    'url_params_data_paths' => 'ShadowAttribute.event_id',
                    'url' => $baseurl . '/events/view',
                ),
                array(
                    'name' => __('Proposal by'),
                    'element' => 'org',
                    'sort' => 'Org.name',
                    'class' => 'short',
                    'data_path' => 'Org',
                ),
                array(
                    'name' => __('Change requested'),
                    'sort' => 'ShadowAttribute.old_id',
                    'class' => 'shortish',
                    'element' => 'boolean',
                    'data_path' => 'ShadowAttribute.old_id',
                ),
                array(
                    'name' => __('Event creator'),
                    'class' => 'shortish',
                    'element' => 'org',
                    'data_path' => 'Event.Orgc',
                ),
                array(
                    'name' => __('Event info'),
                    'class' => 'short',
                    'sort' => 'Event.info',
                    'data_path' => 'Event.info'
                ),
                array(
                    'name' => __('Proposed value'),
                    'data_path' => 'ShadowAttribute.value',
                    'sort' => 'ShadowAttribute.value'
                ),
                array(
                    'name' => __('Category'),
                    'class' => 'short',
                    'data_path' => 'ShadowAttribute.category',
                    'sort' => 'ShadowAttribute.category',
                ),
                array(
                    'name' => __('Type'),
                    'class' => 'short',
                    'data_path' => 'ShadowAttribute.type',
                    'sort' => 'ShadowAttribute.type',
                ),
                array(
                    'name' => __('Created'),
                    'class' => 'short',
                    'element' => 'datetime',
                    'data_path' => 'ShadowAttribute.timestamp',
                    'sort' => 'ShadowAttribute.timestamp'
                ),
            ),
            'title' => __('Proposals'),
            'actions' => array(
                array(
                    'url' => $baseurl . '/events/view',
                    'url_params_data_paths' => 'ShadowAttribute.event_id',
                    'url_named_params_data_paths' => ['focus' => 'ShadowAttribute.uuid'],
                    'icon' => 'eye',
                    'title' => __('View Event'),
                    'dbclickAction' => true,
                ),
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'viewProposals'));
?>
<script type="text/javascript">
    $(function(){
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
