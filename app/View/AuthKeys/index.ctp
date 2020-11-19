<?php
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
                        'data' => '',
                        'searchKey' => 'value'
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
                ],
                [
                    'name' => __('Auth key'),
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
                    'name' => __('Comment'),
                    'sort' => 'AuthKey.comment',
                    'data_path' => 'AuthKey.comment',
                ],
            ],
            'title' => empty($ajax) ? __('Authentication key Index') : false,
            'description' => empty($ajax) ? __('A list of API keys bound to a user.') : false,
            'pull' => 'right',
            'actions' => [
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
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => $metaGroup, 'menuItem' => $this->action));
    }
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(document).ready(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
        $('#quickFilterField').on('keypress', function (e) {
            if(e.which === 13) {
                runIndexQuickFilter();
            }
        });
    });
</script>
