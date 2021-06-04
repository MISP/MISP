<?php
    if (!$advancedEnabled) {
        echo '<div class="alert">' . __('Advanced auth keys are not enabled.') . '</div>';
    }
    echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
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
                                'text' => __('Add authentication key'),
                                'class' => 'btn btn-primary',
                                'onClick' => 'openGenericModal',
                                'onClickParams' => [
                                    sprintf(
                                        '%s/auth_keys/add%s',
                                        $baseurl,
                                        empty($user_id) ? '' : ('/' . $user_id)
                                    )
                                ]
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
                    'sort' => 'AuthKey.id',
                    'data_path' => 'AuthKey.id',
                ],
                [
                    'name' => __('User'),
                    'sort' => 'User.email',
                    'data_path' => 'User.email',
                    'element' => empty($user_id) ? 'links' : 'generic_field',
                    'url' => $baseurl . '/users/view',
                    'url_params_data_paths' => ['User.id'],
                ],
                [
                    'name' => __('Auth Key'),
                    'sort' => 'AuthKey.authkey_start',
                    'element' => 'authkey',
                    'data_path' => 'AuthKey',
                ],
                [
                    'name' => __('Expiration'),
                    'sort' => 'AuthKey.expiration',
                    'data_path' => 'AuthKey.expiration',
                    'element' => 'expiration'
                ],
                [
                    'name' => ('Last used'),
                    'data_path' => 'AuthKey.last_used',
                    'element' => 'datetime',
                    'requirements' => $keyUsageEnabled,
                    'empty' => __('Never'),
                ],
                [
                    'name' => __('Comment'),
                    'sort' => 'AuthKey.comment',
                    'data_path' => 'AuthKey.comment',
                ],
                [
                    'name' => __('Allowed IPs'),
                    'data_path' => 'AuthKey.allowed_ips',
                ],
            ],
            'title' => empty($ajax) ? __('Authentication key Index') : false,
            'description' => empty($ajax) ? __('A list of API keys bound to a user.') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'url' => $baseurl . '/auth_keys/view',
                    'url_params_data_paths' => array(
                        'AuthKey.id'
                    ),
                    'icon' => 'eye',
                    'dbclickAction' => true,
                    'title' => 'View auth key',
                ],
                [
                    'url' => $baseurl . '/auth_keys/edit',
                    'url_params_data_paths' => array(
                        'AuthKey.id'
                    ),
                    'icon' => 'edit',
                    'title' => 'Edit auth key',
                ],
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/authKeys/delete/[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'AuthKey.id',
                    'icon' => 'trash',
                    'title' => __('Delete auth key'),
                ]
            ]
        ]
    ]);
    echo '</div>';
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
    }
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
