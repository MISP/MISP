<?php
if ($isSiteAdmin) {
    $this->set('menuData', ['menuList' => 'admin', 'menuItem' => 'eventBlocklists']);
} else {
    $this->set('menuData', ['menuList' => 'event-collection', 'menuItem' => 'eventBlocklists']);
}
echo $this->element('genericElements/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $response,
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
                            'value_path' => 'EventBlocklist.id'
                        ]
                    ]
                ],
                [
                    'name' => 'Id',
                    'sort' => 'EventBlocklist.id',
                    'data_path' => 'EventBlocklist.id'
                ],
                [
                    'name' => 'Organisation name',
                    'sort' => 'EventBlocklist.org_name',
                    'data_path' => 'EventBlocklist.event_orgc'
                ],
                [
                    'name' => 'UUID',
                    'sort' => 'EventBlocklist.event_uuid',
                    'data_path' => 'EventBlocklist.event_uuid'
                ],
                [
                    'name' => 'Created',
                    'sort' => 'EventBlocklist.created',
                    'data_path' => 'EventBlocklist.created',
                    'element' => 'datetime'
                ],
                [
                    'name' => 'Event Info',
                    'sort' => 'EventBlocklist.event_info',
                    'data_path' => 'EventBlocklist.event_info',
                    'class' => 'bitwider'
                ],
                [
                    'name' => 'Comment',
                    'sort' => 'EventBlocklist.comment',
                    'data_path' => 'EventBlocklist.comment',
                    'class' => 'bitwider'
                ],
            ],
            'title' => empty($ajax) ? __('Event Blocklists') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'url' => $baseurl . '/event_blocklists/edit',
                    'url_params_data_paths' => [
                        'EventBlocklist.id'
                    ],
                    'icon' => 'edit',
                    'title' => 'Edit Blocklist',
                ],
                [
                    'url' => $baseurl . '/event_blocklists/delete',
                    'url_params_data_paths' => [
                        'EventBlocklist.id'
                    ],
                    'icon' => 'trash',
                    'title' => 'Delete Blocklist',
                ]
            ]
        ]
    ]
]);
