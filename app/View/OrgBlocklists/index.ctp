<?php
$this->set('menuData', ['menuList' => 'admin', 'menuItem' => 'orgBlocklists']);
echo $this->element('genericElements/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $response,
            'fields' => [
                [
                    'name' => 'Id',
                    'sort' => 'OrgBlocklist.id',
                    'data_path' => 'OrgBlocklist.id'
                ],
                [
                    'name' => 'Organisation name',
                    'sort' => 'OrgBlocklist.org_name',
                    'data_path' => 'OrgBlocklist.org_name'
                ],
                [
                    'name' => 'UUID',
                    'sort' => 'OrgBlocklist.org_uuid',
                    'data_path' => 'OrgBlocklist.org_uuid'
                ],
                [
                    'name' => 'Created',
                    'sort' => 'OrgBlocklist.created',
                    'data_path' => 'OrgBlocklist.created',
                    'element' => 'datetime'
                ],
                [
                    'name' => 'Comment',
                    'sort' => 'OrgBlocklist.comment',
                    'data_path' => 'OrgBlocklist.comment',
                    'class' => 'bitwider'
                ],

            ],
            'title' => empty($ajax) ? __('Organisation Blocklists') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'url' => $baseurl . '/org_blocklists/edit',
                    'url_params_data_paths' => array(
                        'OrgBlocklist.id'
                    ),
                    'icon' => 'edit',
                    'title' => 'Edit Blocklist',
                ],
                [
                    'url' => $baseurl . '/org_blocklists/delete',
                    'url_params_data_paths' => array(
                        'OrgBlocklist.id'
                    ),
                    'icon' => 'trash',
                    'title' => 'Delete Blocklist',
                ]
            ]
        ]
    ]
]);
