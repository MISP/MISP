<?php
    echo '<div class="index">';
    echo '<a href="' . $baseurl . '/events/restoreDeletedEvents">' . __('Return to the event restoration index') . '</a>';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'skip_pagination' => true,
            'data' => $data,
            'fields' => [
                [
                    'name' => __('Model'),
                    'class' => 'short',
                    'data_path' => 'model'
                ],
                [
                    'name' => __('Action'),
                    'class' => 'short',
                    'data_path' => 'action'
                ],
                [
                    'name' => __('Data'),
                    'class' => 'short',
                    'data_path' => 'data',
                    'element' => 'json'
                ],
            ],
            'title' => __('Recovery process log'),
            'description' => __('Below is a list of actions the recovery process would take in order to restore the event.')
        ]
    ]);
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'admin', 'menuItem' => 'restore_deleted_events']);
?>
