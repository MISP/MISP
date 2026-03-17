<?php
    echo '<div class="servers index">';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'title' => __('Servers'),
            'data' => $servers,
            'primary_id_path' => 'Server.id',
            'fields' => [
                [
                    'name' => __('ID'),
                    'sort' => 'Server.id',
                    'class' => 'short',
                    'data_path' => 'Server.id',
                ],
                [
                    'name' => __('Name'),
                    'sort' => 'Server.name',
                    'class' => 'short',
                    'data_path' => 'Server.name',
                ],
                [
                    'name' => __('Prio'),
                    'element' => 'server_prio',
                ],
                [
                    'name' => __('Connection test'),
                    'element' => 'server_button',
                    'class' => 'short',
                    'button' => [
                        'label' => __('Run'),
                        'js_action' => 'testConnection',
                        'js_param_path' => 'Server.id',
                        'cell_id' => 'connection_test_%s',
                        'cell_id_param_path' => 'Server.id',
                        'class' => 'btn btn-primary',
                        'style' => 'line-height:10px; padding: 4px 4px;',
                        'title' => __('Test the connection to the remote instance'),
                        'aria_label' => __('Test the connection to the remote instance'),
                    ],
                ],
                [
                    'name' => __('Sync user'),
                    'element' => 'server_button',
                    'class' => 'short',
                    'button' => [
                        'label' => __('View'),
                        'js_action' => 'getRemoteSyncUser',
                        'js_param_path' => 'Server.id',
                        'cell_id' => 'sync_user_test_%s',
                        'cell_id_param_path' => 'Server.id',
                        'class' => 'btn btn-primary',
                        'style' => 'line-height:10px; padding: 4px 4px;',
                        'title' => __('View the sync user of the remote instance'),
                        'aria_label' => __('View the sync user of the remote instance'),
                    ],
                    'data_html' => '<span role="button" tabindex="0" aria-label="' . __('View the sync user of the remote instance') . '" title="' . __('View the sync user of the remote instance') . '" class="btn btn-primary" style="line-height:10px; padding: 4px 4px;" onClick="getRemoteSyncUser(%s);">' . __('View') . '</span>',
                ],
                [
                    'name' =>  __('Reset API key'),
                    'element' => 'postlink',
                    'data_path' => 'Server.id',
                    'url' => '/servers/resetRemoteAuthKey/%s',
                    'url_params_data_paths' => 'Server.id',
                    'decorator' => function ($content) {
                        $label = __('Remotely reset API key');
                        $text = __('Reset');

                        $content = preg_replace(
                            '/>([^<]*)<\/a>/',
                            '> ' . $text . '</a>',
                            $content
                        );

                        $content = preg_replace(
                            '/<a /',
                            '<a class="btn btn-primary" ' .
                            'style="line-height:10px; padding: 4px 4px;" ' .
                            'title="' . h($label) . '" ' .
                            'aria-label="' . h($label) . '" ',
                            $content,
                            1
                        );

                        return $content;
                    },
                ],
                [
                    'name' => __('Internal'),
                    'sort' => 'Server.internal',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.internal'
                ],
                [
                    'name' => __('Push'),
                    'sort' => 'Server.push',
                    'element' => 'server_push_pull',
                    'mode' => 'push',
                ],
                [
                    'name' => __('Pull'),
                    'sort' => 'Server.pull',
                    'element' => 'server_push_pull',
                    'mode' => 'pull',           ],
                [
                    'name' => __('Push Sightings'),
                    'sort' => 'Server.push_sightings',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.push_sightings'
                ],
                [
                    'name' => __('Push Clusters'),
                    'sort' => 'Server.push_galaxy_clusters',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.push_galaxy_clusters'
                ],
                [
                    'name' => __('Pull Clusters'),
                    'sort' => 'Server.pull_galaxy_clusters',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.pull_galaxy_clusters'
                ],
                [
                    'name' => __('Push Analyst Data'),
                    'sort' => 'Server.push_analyst_data',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.push_analyst_data'
                ],
                [
                    'name' => __('Pull Analyst Data'),
                    'sort' => 'Server.pull_analyst_data',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.pull_analyst_data'
                ],
                [
                    'name' => __('Cache'),
                    'sort' => 'Server.caching_enabled',
                    'element' => 'cache_status',
                    'data_path' => 'Server.caching_enabled'
                ],
                [
                    'name' => __('Unpublish Event'),
                    'sort' => 'Server.unpublish_event',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.unpublish_event'
                ],
                [
                    'name' => __('Publish Without Email'),
                    'sort' => 'Server.publish_without_email',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.publish_without_email'
                ],
                [
                    'name' => __('URL'),
                    'sort' => 'Server.url',
                    'data_path' => 'Server.url',
                ],
                [
                    'name' => __('Remote Organisation'),
                    'element' => 'simple_link',
                    'data_path' => 'RemoteOrg.name',
                    'link_title_path' => 'RemoteOrg.name',
                    'url' => function (array $row) {
                        return '/organisations/view/' . $row['RemoteOrg']['id'];
                    }
                ],
                [
                    'name' => __('Cert File'),
                    'sort' => 'Server.cert_file',
                    'class' => 'short',
                    'data_path' => 'Server.cert_file',
                ],
                [
                    'name' => __('Client Cert File'),
                    'sort' => 'Server.client_cert_file',
                    'class' => 'short',
                    'data_path' => 'Server.client_cert_file',
                ],
                [
                    'name' => __('Self Signed'),
                    'sort' => 'Server.self_signed',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.self_signed'
                ],
                [
                    'name' => __('Skip Proxy'),
                    'sort' => 'Server.skip_proxy',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Server.skip_proxy'
                ],
                [
                    'name' => __('Organisation'),
                    'sort' => 'Organisation.name',
                    'element' => 'simple_link',
                    'data_path' => 'Organisation.name',
                    'link_title_path' => 'Organisation.name',
                    'url' => function (array $row) {
                        return '/organisations/view/' . $row['Organisation']['id'];
                    }
                ],
                [
                    'name' => __('Bound Sync Users'),
                    'sort' => 'BoundUsers.email',
                    'class' => 'short',
                    'data_path' => 'BoundUsers',
                ],
            ],
            'actions' => [
                [
                    'url' => $baseurl . '/servers/previewIndex',
                    'url_params_data_paths' => [
                        'Server.id'
                    ],
                    'icon' => 'search',
                    'title' => __('Explore')
                ],
                [
                    'url' => $baseurl . '/servers/pull',
                    'url_params_data_paths' => [
                        'Server.id',
                        'update'
                    ],
                    'icon' => 'sync',
                    'title' => __('Pull updates to events that already exist locally'),
                    'complex_requirement' => [
                        'function' => function ($row) {
                            return !empty($row['Server']['pull']);
                        }
                    ]
                ],
                [
                    'url' => $baseurl . '/servers/pull',
                    'url_params_data_paths' => [
                        'Server.id',
                        'full'
                    ],
                    'icon' => 'arrow-circle-down',
                    'title' => __('Pull all'),
                    'complex_requirement' => [
                        'function' => function ($row) {
                            return !empty($row['Server']['pull']);
                        }
                    ]
                ],
                [
                    'url' => $baseurl . '/servers/pull',
                    'url_params_data_paths' => [
                        'Server.id',
                        'pull_relevant_clusters'
                    ],
                    'icon' => 'tags',
                    'title' => __('Pull known relevant custom clusters'),
                    'complex_requirement' => [
                        'function' => function ($row) {
                            return !empty($row['Server']['pull']) && !empty($row['Server']['pull_galaxy_clusters']);
                        }
                    ]
                ],
                [
                    'url' => $baseurl . '/servers/push',
                    'url_params_data_paths' => [
                        'Server.id',
                        'full'
                    ],
                    'icon' => 'arrow-circle-up',
                    'title' => __('Push all'),
                    'complex_requirement' => [
                        'function' => function ($row) {
                            return !empty($row['Server']['push']);
                        }
                    ]
                ],
                [
                    'url' => $baseurl . '/servers/cache',
                    'url_params_data_paths' => [
                        'Server.id'
                    ],
                    'icon' => 'memory',
                    'title' => __('Cache instance'),
                    'complex_requirement' => [
                        'function' => function ($row) {
                            return !empty($row['Server']['caching_enabled']);
                        }
                    ]
                ],
                [
                    'url' => $baseurl . '/servers/edit',
                    'url_params_data_paths' => [
                        'Server.id'
                    ],
                    'icon' => 'edit',
                    'title' => __('Edit'),
                    'requirement' => $isSiteAdmin,
                ],
                [
                    'url' => $baseurl . '/servers/delete',
                    'url_params_data_paths' => [
                        'Server.id'
                    ],
                    'postLink' => '',
                    'postLinkConfirm' => __('Are you sure you want to delete the Server?'),
                    'icon' => 'trash',
                    'title' => __('Delete server'),
                    'requirement' => $isSiteAdmin,
                ]
            ]
        ]
    ]);
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'index'));
?>
<script type="text/javascript">
    $(function(){
        popoverStartup();
        $('.rearrange-up').click(function() {
            moveIndexRow($(this).data('server-id'), 'up', '/servers/changePriority');
        });
        $('.rearrange-down').click(function() {
            moveIndexRow($(this).data('server-id'), 'down', '/servers/changePriority');
        });
    });
</script>
