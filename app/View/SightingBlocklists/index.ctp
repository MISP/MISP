<?php
$this->set('menuData', ['menuList' => 'admin', 'menuItem' => 'sightingBlocklists']);
echo $this->element('genericElements/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $response,
            'fields' => [
                [
                    'name' => 'Id',
                    'sort' => 'SightingBlocklist.id',
                    'data_path' => 'SightingBlocklist.id'
                ],
                [
                    'name' => 'Organisation name',
                    'sort' => 'SightingBlocklist.org_name',
                    'data_path' => 'SightingBlocklist.org_name'
                ],
                [
                    'name' => 'UUID',
                    'sort' => 'SightingBlocklist.org_uuid',
                    'data_path' => 'SightingBlocklist.org_uuid'
                ],
                [
                    'name' => 'Created',
                    'sort' => 'SightingBlocklist.created',
                    'data_path' => 'SightingBlocklist.created',
                    'element' => 'datetime'
                ],
                [
                    'name' => 'Comment',
                    'sort' => 'SightingBlocklist.comment',
                    'data_path' => 'SightingBlocklist.comment',
                    'class' => 'bitwider'
                ],
                [
                    'name' => 'Blocked amount',
                    'sort' => 'SightingBlocklist.blocked_data.blocked_amount',
                    'data_path' => 'SightingBlocklist.blocked_data.blocked_amount',
                ],
                [
                    'name' => 'Blocked last time ',
                    'sort' => 'SightingBlocklist.blocked_data.blocked_last_time',
                    'data_path' => 'SightingBlocklist.blocked_data.blocked_last_time',
                    'element' => 'datetime'
                ],

            ],
            'title' => empty($ajax) ? __('Sighting Blocklists') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'url' => $baseurl . '/org_blocklists/edit',
                    'url_params_data_paths' => array(
                        'SightingBlocklist.id'
                    ),
                    'icon' => 'edit',
                    'title' => 'Edit Blocklist',
                ],
                [
                    'url' => $baseurl . '/org_blocklists/delete',
                    'url_params_data_paths' => array(
                        'SightingBlocklist.id'
                    ),
                    'icon' => 'trash',
                    'title' => 'Delete Blocklist',
                ]
            ]
        ]
    ]
]);
