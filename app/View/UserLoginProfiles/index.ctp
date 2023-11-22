<?php
    echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
    echo $this->element('genericElements/IndexTable/index_table', [
        'data' => [
            'data' => $data,
            'top_bar' => [
                'pull' => 'right',
                'children' => [
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
                    'sort' => 'UserLoginProfile.id',
                    'data_path' => 'UserLoginProfile.id',
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
                    'name' => __('IP'),
                    'sort' => 'UserLoginProfile.ip',
                    'data_path' => 'UserLoginProfile.ip',
                ],
                [
                    'name' => __('User-Agent'),
                    'sort' => 'UserLoginProfile.user_agent',
                    'data_path' => 'UserLoginProfile.user_agent',
                ],
                [
                    'name' => ('Reported on'),
                    'data_path' => 'UserLoginProfile.created_at',
                    'element' => 'datetime',
                    'empty' => __('Never'),
                ],
                [
                    'name' => __('Status'),
                    'sort' => 'UserLoginProfile.status',
                    'data_path' => 'UserLoginProfile.status',
                ],
                [
                    'name' => __('Accept Language'),
                    'sort' => 'UserLoginProfile.accept_lang',
                    'data_path' => 'UserLoginProfile.accept_lang',
                ],
                [
                    'name' => __('GeoIP'),
                    'sort' => 'UserLoginProfile.geoip',
                    'data_path' => 'UserLoginProfile.geoip',
                ],
                [
                    'name' => __('UA.pattern'),
                    'sort' => 'UserLoginProfile.ua_pattern',
                    'data_path' => 'UserLoginProfile.ua_',
                ],
                [
                    'name' => __('UA.Platform'),
                    'sort' => 'UserLoginProfile.ua_platform',
                    'data_path' => 'UserLoginProfile.ua_platform',
                ],
                [
                    'name' => __('UA.Browser'),
                    'sort' => 'UserLoginProfile.ua_browser',
                    'data_path' => 'UserLoginProfile.ua_browser',
                ]
            ],
            'title' => empty($ajax) ? __('UserLoginProfile Index') : false,
            'description' => empty($ajax) ? __('A list of confirmed authentication profiles bound to a user. This is used by the backend to identify suspicious connections from a user and raise alerts.') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'class' => 'modal-open',
                    'url' => "$baseurl/admin/UserLoginProfiles/delete",
                    'url_params_data_paths' => ['UserLoginProfile.id'],
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete this profile?'),    
                    'icon' => 'trash',
                    'title' => __('Delete entry'),
                    'requirement' => $delete_buttons
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
