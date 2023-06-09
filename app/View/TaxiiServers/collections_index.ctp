<?php
    echo $this->element('genericElements/IndexTable/scaffold', [
        'skip_pagination' => 1,
        'scaffold_data' => [
            'data' => [
                
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                    ]
                ],
                'fields' => [
                    [
                        'name' => __('Id'),
                        'sort' => 'id',
                        'data_path' => 'id'
                    ],
                    [
                        'name' => __('Title'),
                        'sort' => 'title',
                        'data_path' => 'title'
                    ],
                    [
                        'name' => __('Description'),
                        'data_path' => 'description'
                    ],
                    [
                        'name' => __('Writeable'),
                        'sort' => 'can_write',
                        'element' => 'boolean',
                        'data_path' => 'can_write'
                    ],
                    [
                        'name' => __('Readable'),
                        'sort' => 'can_read',
                        'element' => 'boolean',
                        'data_path' => 'can_read'
                    ],
                    [
                        'name' => __('Media types'),
                        'element' => 'list',
                        'data_path' => 'media_types'
                    ]
                ],
                'title' => empty($ajax) ? __('The collections found on TaxiiServer #%s.', h($id)) : false,
                'description' => false,
                'actions' => [
                    [
                        'url' => $baseurl . '/taxiiServers/objectsIndex/' . h($id) . '/%s/',
                        'url_replace' => ['id'],
                        'icon' => 'eye'
                    ]
                ]
            ]
        ]
    ]);

?>