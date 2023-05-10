<?php
if ($isSiteAdmin) {
    $this->set('menuData', ['menuList' => 'admin', 'menuItem' => 'eventBlocklists']);
} else {
    $this->set('menuData', ['menuList' => 'event-collection', 'menuItem' => 'eventBlocklists']);
}
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'pull' => 'right',
            'children' => [
                [
                    'children' => [
                        [
                            'class' => 'hidden mass-select',
                            'fa-icon' => 'trash',
                            'onClick' => "multiSelectDeleteEventBlocklist",
                            'onClickParams' => ['1', '0']
                        ]
                    ]
                ],
                [
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'searchKey' => 'searchall',
                ]
            ]
        ],
        'fields' => [
            [
                'element' => 'selector',
                'class' => 'short',
                'data' => [
                    'id' => [
                        'value_path' => 'id'
                    ]
                ]
            ],
            [
                'name' => 'Id',
                'sort' => 'id',
                'data_path' => 'id'
            ],
            [
                'name' => 'Organisation name',
                'sort' => 'org_name',
                'data_path' => 'event_orgc'
            ],
            [
                'name' => 'UUID',
                'sort' => 'event_uuid',
                'data_path' => 'event_uuid'
            ],
            [
                'name' => 'Created',
                'sort' => 'created',
                'data_path' => 'created',
                'element' => 'datetime'
            ],
            [
                'name' => 'Event Info',
                'sort' => 'event_info',
                'data_path' => 'event_info',
                'class' => 'bitwider'
            ],
            [
                'name' => 'Comment',
                'sort' => 'comment',
                'data_path' => 'comment',
                'class' => 'bitwider'
            ],
        ],
        'title' => empty($ajax) ? __('Event Blocklists') : false,
        'pull' => 'right',
        'actions' => [
            [
                'url' => $baseurl . '/event_blocklists/edit',
                'url_params_data_paths' => [
                    'id'
                ],
                'icon' => 'edit',
                'title' => 'Edit Blocklist',
            ],
            [
                'url' => $baseurl . '/event_blocklists/delete',
                'url_params_data_paths' => [
                    'id'
                ],
                'icon' => 'trash',
                'title' => 'Delete Blocklist',
            ]
        ]
    ]
]);
