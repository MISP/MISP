<?php
    echo '<div class="index">';
    if ($isSiteAdmin) {
        echo '<div id="hiddenFormDiv">';
        echo $this->Form->create('Warninglist', array('url' => $baseurl . '/warninglists/toggleEnable'));
        echo $this->Form->input('data', array('label' => false, 'style' => 'display:none;'));
        echo $this->Form->end();
        echo '</div>';
    }
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $warninglists,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'url' => $baseurl . '/warninglists/index',
                                'text' => __('All'),
                                'active' => !isset($passedArgsArray['enabled']),
                            ),
                            array(
                                'url' => $baseurl . '/warninglists/index/enabled:1',
                                'text' => __('Enabled'),
                                'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "1",
                            ),
                            array(
                                'url' => $baseurl . '/warninglists/index/enabled:0',
                                'text' => __('Disabled'),
                                'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "0",
                            )
                        )
                    ),
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value'
                    )
                )
            ),
            'title' => __('Warninglists'),
            'primary_id_path' => 'Warninglist.id',
            'fields' => array(
                array(
                    'name' => __('ID'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'Warninglist.id',
                    'element' => 'links',
                    'url' => $baseurl . '/warninglists/view/%s'
                ),
                array(
                    'name' => __('Name'),
                    'sort' => 'name',
                    'data_path' => 'Warninglist.name',
                ),
                array(
                    'name' => __('Version'),
                    'sort' => 'version',
                    'class' => 'short',
                    'data_path' => 'Warninglist.version',
                ),
                array(
                    'name' => __('Description'),
                    'data_path' => 'Warninglist.description',
                ),
                array(
                    'name' => __('Type'),
                    'sort' => 'type',
                    'class' => 'short',
                    'data_path' => 'Warninglist.type',
                ),
                array(
                    'name' => __('Valid attributes'),
                    'class' => 'short',
                    'sort' => 'Warninglist.valid_attributes',
                    'data_path' => 'Warninglist.valid_attributes',
                ),
                array(
                    'name' => __('Entries'),
                    'sort' => 'warninglist_entry_count',
                    'class' => 'short',
                    'data_path' => 'Warninglist.warninglist_entry_count',
                ),
                array(
                    'name' => __('Enabled'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'Warninglist.enabled',
                ),
            ),
            'actions' => array(
                array(
                    'title' => __('Enable'),
                    'icon' => 'play',
                    'onclick' => sprintf('toggleSetting(%s, \'%s\', \'%s\')', 'event', 'warninglist_enable', '[onclick_params_data_path]'),
                    'onclick_params_data_path' => 'Warninglist.id',
                    'complex_requirement' => array(
                        'function' => function ($row, $options) {
                            return $options['me']['Role']['perm_site_admin'] && !$options['datapath']['enabled'];
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'orgc' => 'Event.orgc_id',
                                'enabled' => 'Warninglist.enabled'
                            )
                        )
                    ),
                ),
                array(
                    'title' => __('Disable'),
                    'icon' => 'stop',
                    'onclick' => sprintf('toggleSetting(%s, \'%s\', \'%s\')', 'event', 'warninglist_enable', '[onclick_params_data_path]'),
                    'onclick_params_data_path' => 'Warninglist.id',
                    'complex_requirement' => array(
                        'function' => function ($row, $options) {
                            return $options['me']['Role']['perm_site_admin'] && $options['datapath']['enabled'];
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'enabled' => 'Warninglist.enabled'
                            )
                        )
                    ),
                ),
                array(
                    'url' => $baseurl . '/warninglists/view',
                    'url_params_data_paths' => array(
                        'Warninglist.id'
                    ),
                    'icon' => 'eye',
                    'dbclickAction' => true
                ),
                array(
                    'title' => __('Delete'),
                    'url' => $baseurl . '/warninglists/delete',
                    'url_params_data_paths' => array(
                        'Warninglist.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the entry?'),
                    'icon' => 'trash',
                    'requirement' => $me['Role']['perm_site_admin'],
                ),
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'warninglist', 'menuItem' => 'index'));
?>

<script type="text/javascript">
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
