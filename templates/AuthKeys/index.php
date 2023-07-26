<?php
echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
if (!$advancedEnabled) {
    echo '<div class="alert">' . __('Advanced auth keys are not enabled.') . '</div>';
}
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'pull' => 'right',
            'children' => [
                [
                    'type' => 'simple',
                    'children' => [
                        'data' => [
                            'type' => 'simple',
                            'fa-icon' => 'plus',
                            'text' => __('Add authentication key'),
                            'class' => 'btn-primary modal-open',
                            'url' => '/auth-keys/add' . (empty($user_id) ? '' : ('/' . $user_id)),
                            'requirement' => $canCreateAuthkey
                        ]
                    ]
                ],
                [
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'searchKey' => 'quickFilter',
                ]
            ]
        ],
        'fields' => [
            [
                'name' => '#',
                'sort' => 'id',
                'data_path' => 'id',
            ],
            [
                'name' => __('User'),
                'sort' => 'User.email',
                'data_path' => 'User.email',
                'url' => '/users/view',
                'url_params_data_paths' => ['User.id'],
                'requirement' => $loggedUser['Role']['perm_admin'] || $loggedUser['Role']['perm_site_admin'],
            ],
            [
                'name' => __('Auth Key'),
                'sort' => 'authkey_start',
                'element' => 'authkey',
                'data_path' => 'AuthKey',
            ],
            [
                'name' => __('Expiration'),
                'sort' => 'expiration',
                'data_path' => 'expiration',
                'element' => 'expiration'
            ],
            [
                'name' => ('Last used'),
                'data_path' => 'last_used',
                'element' => 'datetime',
                'requirements' => $keyUsageEnabled,
                'empty' => __('Never'),
            ],
            [
                'name' => __('Comment'),
                'sort' => 'comment',
                'data_path' => 'comment',
            ],
            [
                'name' => __('Allowed IPs'),
                'data_path' => 'allowed_ips',
            ],
            [
                'name' => __('Seen IPs'),
                'data_path' => 'unique_ips',
                'element' => 'authkey_pin',
            ]
        ],
        'title' => empty($ajax) ? __('Authentication key Index') : false,
        'description' => empty($ajax) ? __('A list of API keys bound to a user.') : false,
        'pull' => 'right',
        'actions' => [
            [
                'url' => '/auth-keys/view',
                'url_params_data_paths' => array(
                    'id'
                ),
                'icon' => 'eye',
                'title' => 'View auth key',
            ],
            [
                'url' => '/auth-keys/edit',
                'url_params_data_paths' => array(
                    'id'
                ),
                'icon' => 'edit',
                'title' => 'Edit auth key',
                'requirement' => $canCreateAuthkey
            ],
            [
                'class' => 'modal-open',
                'url' => '/authKeys/delete',
                'url_params_data_paths' => ['id'],
                'icon' => 'trash',
                'title' => __('Delete auth key'),
                'requirement' => $canCreateAuthkey
            ]
        ]
    ]
]);
echo '</div>';
// TODO: [3.x-MIGRATION]
// if (empty($ajax)) {
//     echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
// }
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>