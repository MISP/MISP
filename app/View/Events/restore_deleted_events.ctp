<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'skip_pagination' => true,
            'data' => $data,
            'fields' => [
                [
                    'name' => __('Event Id'),
                    'class' => 'short',
                    'data_path' => 'event_id'
                ],
                [
                    'name' => __('Event Info'),
                    'data_path' => 'event_info'
                ],
                [
                    'name' => __('Creation time'),
                    'class' => 'short',
                    'data_path' => 'event_created'
                ],
                [
                    'name' => __('Deletion time'),
                    'class' => 'short',
                    'data_path' => 'created'
                ],
                [
                    'name' => __('Event Creator'),
                    'class' => 'short',
                    'data_path' => 'event_orgc_name'
                ],
                [
                    'name' => __('Event Owner'),
                    'class' => 'short',
                    'data_path' => 'event_orgc_name'
                ],
                [
                    'name' => __('Event Creator'),
                    'class' => 'short',
                    'data_path' => 'event_user_name'
                ],
                [
                    'name' => __('Deleted By'),
                    'class' => 'short',
                    'data_path' => 'user_name'
                ]
            ],
            'title' => __('Restore Deleted Events'),
            'description' => __('Below are a list of events that can be recovered via the log entries. Make sure that your log table is well indexed (adding indeces to `model`, `model_id`, `created` and `action` highly recommended).'),
            'actions' => [
                [
                    'url' => $baseurl . '/events/recoverEvent',
                    'url_params_data_paths' => [
                        'event_id',
                        'event_id'
                    ],
                    'title' => __('Mock the recovery process and output the potential changes'),
                    'postLink' => 1,
                    'postLinkConfirm' => __('Are you sure you want to mock the recovery of the event? No data will be modified, but the request might take some time.'),
                    'icon' => 'flask'
                ],
                [
                    'url' => $baseurl . '/events/recoverEvent',
                    'url_params_data_paths' => [
                        'event_id'
                    ],
                    'title' => __('Execute the recovery process'),
                    'postLink' => 1,
                    'postLinkConfirm' => __('Are you sure you want to attempt to recover the event?'),
                    'icon' => 'trash-restore'
                ]
            ]
        ]
    ]);
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'admin', 'menuItem' => 'restore_deleted_events']);
?>
<script type="text/javascript">

</script>
